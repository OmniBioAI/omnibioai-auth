"""HIPAA Phase 3: MFA/TOTP challenge brute-force protection.

Policy layer on top of `app/core/rate_limit.py`'s atomic Redis primitives
-- the same module `login_throttle_service.py` (HIPAA Phase 1 PR1) uses,
reused here rather than duplicated (see that module's docstring for why
it's already generic over key/threshold), but with an entirely separate,
independently-tunable policy (`MFA_RATE_LIMIT_*` in config.py) and its own
Redis key namespace (`mfaratelimit:*`, never `ratelimit:*`) so the two
controls can never share, corrupt, or shadow each other's counters.

Scoped exclusively to `POST /users/me/mfa/challenge`
(`app.services.mfa_service.verify_mfa_challenge`, its only caller) -- the
one endpoint in this service where an attacker who has already obtained or
guessed a user's password (or completed an OAuth/SSO/license login for
them) can still be stopped by brute-forcing the second factor. See
docs/security-mfa-challenge-throttling.md for the full design, including
why `POST /users/me/mfa/totp/verify` (self-enrollment confirmation,
already gated by a real access token) is deliberately NOT in this file's
scope -- a fundamentally different threat model, not an oversight.

Three independently-configured layers, identical shape to
`login_throttle_service.py`'s account/ip/pair, but keyed on values
available at this endpoint instead:

  account   -- the challenge token's own `user_id` claim, extracted only
               after the token's signature has been verified
               (`app.core.jwt.decode_token`) -- never a client-supplied
               header (`X-User-Id`/`X-Organization-Id`), which this
               endpoint doesn't even read. Primary defense: rotating
               source IP doesn't reset this.
  ip        -- source IP. Secondary/abuse-control dimension only, per
               this control's explicit design requirement -- never relied
               on alone. Catches one source hammering many different
               accounts' challenges.
  pair      -- (user_id, IP) together. The fast circuit-breaker for the
               common single-attacker-single-target case.

No account key needs hashing the way login_throttle_service's does: a
user_id is an opaque internal integer, not an email address, and is
already used unhashed as a plain audit/resource identifier everywhere else
in this service (AuditEvent.target_user_id, URL path params, etc.) -- SS
"Privacy" in docs/security-mfa-challenge-throttling.md for the full
reasoning.
"""
import hashlib

from prometheus_client import Counter
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.core.config import settings
from app.services import audit_service
from app.services.audit_service import AuditEventType

# Bounded label cardinality (3 fixed values), mirroring
# login_throttle_service.RATE_LIMIT_DIMENSION_TRIGGERED -- never
# email/IP/user id as a label.
MFA_RATE_LIMIT_DIMENSION_TRIGGERED = Counter(
    "auth_mfa_rate_limit_dimension_triggered_total",
    "MFA/TOTP challenge lockouts newly triggered, by dimension",
    ["dimension"],
)


def _account_key(user_id: int) -> str:
    return f"mfaratelimit:acct:{user_id}"


def _ip_key(ip: str) -> str:
    return f"mfaratelimit:ip:{ip}"


def _pair_key(user_id: int, ip: str) -> str:
    digest = hashlib.sha256(f"{ip}:{user_id}".encode()).hexdigest()[:16]
    return f"mfaratelimit:pair:{digest}"


def _strike_key(user_id: int) -> str:
    return f"mfaratelimit:strikes:{user_id}"


class MFAThrottleStatus:
    def __init__(self, locked: bool, retry_after_seconds: int = 0):
        self.locked = locked
        self.retry_after_seconds = retry_after_seconds


def check_throttled(user_id: int, ip: str | None) -> MFAThrottleStatus:
    """Read-only peek against all three lock keys -- called from
    `mfa_service.verify_mfa_challenge` as early as possible: right after
    the challenge token's signature has been verified and its `user_id`
    claim extracted, but *before* any device lookup, TOTP secret
    decryption, or recovery-code query runs. A missing `ip` (test
    transports without a real client) degrades to account+pair-with-
    empty-ip protection only, same as login_throttle_service.check_throttled.
    """
    if not settings.MFA_RATE_LIMIT_ENABLED:
        return MFAThrottleStatus(locked=False)

    ip = ip or ""
    # NB: the `:lock` flag keys record_failure sets on threshold
    # crossing -- not the bare fail-counter keys, which carry their own,
    # unrelated window-expiry TTL. Same distinction
    # login_throttle_service.check_throttled draws for its own keys.
    keys = [f"{_account_key(user_id)}:lock", f"{_pair_key(user_id, ip)}:lock"]
    if ip:
        keys.append(f"{_ip_key(ip)}:lock")

    max_retry_after = 0
    locked = False
    for lock_key in keys:
        is_locked, ttl = rate_limit.is_locked(lock_key)
        if is_locked:
            locked = True
            max_retry_after = max(max_retry_after, ttl)

    return MFAThrottleStatus(locked=locked, retry_after_seconds=max_retry_after)


def record_failure(db: Session, user_id: int, ip: str | None, organization_id: int | None = None) -> None:
    """Called exactly once per failed challenge-verification request --
    from `mfa_service.verify_mfa_challenge`'s single terminal failure
    branch, after both the TOTP-device loop and the recovery-code check
    have failed to match `code` against anything. Mirrors
    login_throttle_service.record_failure's "one funnel point, one call"
    shape: never called per-device inside the TOTP-matching loop (that
    would double- or triple-count one HTTP request against a user with
    multiple enrolled devices), and never called for a request rejected
    before that point (malformed/expired/reused/wrong-type token, or a
    user who is no longer active/no longer has MFA enabled) -- those are
    a different failure class already handled by the existing
    MFAChallengeError path, not a TOTP-guessing attempt against a
    resolvable account. See mfa_service.py.
    """
    if not settings.MFA_RATE_LIMIT_ENABLED:
        return

    ip = ip or ""

    account_result = rate_limit.record_attempt(
        _account_key(user_id), f"{_account_key(user_id)}:lock",
        settings.MFA_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS,
        settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS,
        settings.MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS,
        fallback_window_seconds=settings.MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS,
        fallback_max_attempts=settings.MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS,
    )
    if account_result.newly_locked:
        _apply_progressive_escalation(user_id)
        _audit_triggered(db, user_id, ip, organization_id, "account", settings.MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS)

    pair_result = rate_limit.record_attempt(
        _pair_key(user_id, ip), f"{_pair_key(user_id, ip)}:lock",
        settings.MFA_RATE_LIMIT_PAIR_WINDOW_SECONDS,
        settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS,
        settings.MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS,
        fallback_window_seconds=settings.MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS,
        fallback_max_attempts=settings.MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS,
    )
    if pair_result.newly_locked:
        _audit_triggered(db, user_id, ip, organization_id, "pair", settings.MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS)

    if ip:
        ip_result = rate_limit.record_attempt(
            _ip_key(ip), f"{_ip_key(ip)}:lock",
            settings.MFA_RATE_LIMIT_IP_WINDOW_SECONDS,
            settings.MFA_RATE_LIMIT_IP_MAX_ATTEMPTS,
            settings.MFA_RATE_LIMIT_IP_LOCKOUT_SECONDS,
            fallback_window_seconds=settings.MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS,
            fallback_max_attempts=settings.MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS,
        )
        if ip_result.newly_locked:
            _audit_triggered(db, user_id, ip, organization_id, "ip", settings.MFA_RATE_LIMIT_IP_LOCKOUT_SECONDS)


def _apply_progressive_escalation(user_id: int) -> None:
    """Account dimension only -- same shape as
    login_throttle_service._apply_progressive_escalation."""
    strikes = rate_limit.bump_strikes(_strike_key(user_id), settings.MFA_RATE_LIMIT_STRIKE_TTL_SECONDS)
    if strikes <= 1:
        return  # first offense -- base lockout (already applied) stands
    escalated = min(
        settings.MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS * (settings.MFA_RATE_LIMIT_PROGRESSIVE_MULTIPLIER ** (strikes - 1)),
        settings.MFA_RATE_LIMIT_MAX_LOCKOUT_SECONDS,
    )
    if escalated > settings.MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS:
        rate_limit.set_lock_ttl(f"{_account_key(user_id)}:lock", escalated)


def _audit_triggered(
    db: Session, user_id: int, ip: str, organization_id: int | None, dimension: str, lockout_seconds: int
) -> None:
    MFA_RATE_LIMIT_DIMENSION_TRIGGERED.labels(dimension=dimension).inc()
    audit_service.log_event(
        db, AuditEventType.MFA_RATE_LIMIT_TRIGGERED,
        actor_user_id=user_id, target_user_id=user_id, organization_id=organization_id,
        resource_type="user", resource_id=user_id,
        metadata={"ip": ip, "dimension": dimension, "lockout_seconds": lockout_seconds},
    )


def record_success(user_id: int, ip: str | None) -> None:
    """Resets the account and (account, IP) counters/locks/strikes on a
    successful MFA verification (TOTP or recovery code) -- a legitimate
    user who eventually gets their code right shouldn't stay throttled,
    and no stale lockout state should carry into their now-authenticated
    session. Deliberately does NOT clear the IP-wide counter, for the
    identical reason login_throttle_service.record_success doesn't:
    other accounts may still be under active attack from the same
    (possibly shared) IP.
    """
    if not settings.MFA_RATE_LIMIT_ENABLED:
        return

    ip = ip or ""
    acct_key = _account_key(user_id)
    pair_key = _pair_key(user_id, ip)
    rate_limit.clear(acct_key, f"{acct_key}:lock", _strike_key(user_id), pair_key, f"{pair_key}:lock")
