"""HIPAA Phase 1 PR1: local-password login brute-force / abuse protection.

Policy layer on top of `app/core/rate_limit.py`'s atomic Redis primitives.
Scoped exclusively to `/auth/login`'s password path (the only caller of
`app.services.auth_service.authenticate_user`) -- SSO/OAuth/SAML logins
never call this and are unaffected, matching this PR's explicit scope (see
docs/security-auth-rate-limiting.md SS "SSO/SAML/OAuth users").

Three independently-configured layers, all keyed off values available
*before* any credential verification runs:

  account   -- truncated SHA-256 of the submitted email. Defends an
               account against an attacker who varies source IP.
  ip        -- source IP. Defends against an attacker who varies the
               account (spraying/credential stuffing) from one IP.
  pair      -- (account, IP) together. The fast, tight circuit-breaker
               for the common single-attacker-single-target case; this is
               what keeps "just change the email" or "just change the IP"
               from being a trivial bypass -- whichever dimension the
               attacker *didn't* change keeps accumulating against its
               own, broader counter above.

The account key is a hash, not the raw email, so Redis never holds a
plaintext, indefinitely-scannable list of targeted email addresses --
consistent with this PR's privacy requirement. This is a lighter measure
than full anonymization (a known email can still be hashed and looked up
by an attacker with Redis access), documented as such rather than
oversold.
"""
import hashlib

from prometheus_client import Counter
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.core.config import settings
from app.services import audit_service
from app.services.audit_service import AuditEventType

# Bounded label cardinality (3 fixed values) -- never email/IP/user id, per
# this PR's "no high-cardinality labels" observability requirement.
RATE_LIMIT_DIMENSION_TRIGGERED = Counter(
    "auth_rate_limit_dimension_triggered_total",
    "Login rate-limit lockouts newly triggered, by dimension",
    ["dimension"],
)


def _account_key(email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]
    return f"ratelimit:acct:{digest}"


def _ip_key(ip: str) -> str:
    return f"ratelimit:ip:{ip}"


def _pair_key(email: str, ip: str) -> str:
    digest = hashlib.sha256(f"{ip}:{email.strip().lower()}".encode()).hexdigest()[:16]
    return f"ratelimit:pair:{digest}"


def _strike_key(email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]
    return f"ratelimit:strikes:{digest}"


class ThrottleStatus:
    def __init__(self, locked: bool, retry_after_seconds: int = 0):
        self.locked = locked
        self.retry_after_seconds = retry_after_seconds


def check_throttled(email: str, ip: str | None) -> ThrottleStatus:
    """Read-only peek against all three lock keys -- called before
    `authenticate_user` so an already-throttled request never reaches
    bcrypt or the database. A missing `ip` (test transports without a
    real client, per routes_auth.py's existing `request.client` guard)
    degrades to account+pair-with-empty-ip protection only -- IP-based
    throttling simply can't apply without an IP, the same way it
    couldn't before this PR existed.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return ThrottleStatus(locked=False)

    ip = ip or ""
    # NB: these are the `:lock` flag keys `record_failure` sets on
    # threshold crossing -- deliberately not the bare fail-counter keys
    # (`_account_key(email)` etc.), which carry their own, unrelated TTL
    # for window expiry (set by rate_limit.record_attempt's Lua script on
    # each key's first increment) and would make `is_locked` misreport
    # "locked" for the entire counting window after a single failure.
    keys = [f"{_account_key(email)}:lock", f"{_pair_key(email, ip)}:lock"]
    if ip:
        keys.append(f"{_ip_key(ip)}:lock")

    max_retry_after = 0
    locked = False
    for lock_key in keys:
        is_locked, ttl = rate_limit.is_locked(lock_key)
        if is_locked:
            locked = True
            max_retry_after = max(max_retry_after, ttl)

    return ThrottleStatus(locked=locked, retry_after_seconds=max_retry_after)


def record_failure(db: Session, email: str, ip: str | None) -> None:
    """Called after a failed password verification (unknown user, no
    password set, or wrong password -- `auth_service.authenticate_user`
    doesn't distinguish these to this layer, matching the enumeration-
    resistance requirement: throttling behaves identically regardless of
    *why* the attempt failed or whether the account exists).
    """
    if not settings.RATE_LIMIT_ENABLED:
        return

    ip = ip or ""

    account_result = rate_limit.record_attempt(
        _account_key(email), f"{_account_key(email)}:lock",
        settings.RATE_LIMIT_ACCOUNT_WINDOW_SECONDS,
        settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS,
        settings.RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS,
    )
    if account_result.newly_locked:
        _apply_progressive_escalation(email)
        _audit_triggered(db, email, ip, "account", settings.RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS)

    pair_result = rate_limit.record_attempt(
        _pair_key(email, ip), f"{_pair_key(email, ip)}:lock",
        settings.RATE_LIMIT_PAIR_WINDOW_SECONDS,
        settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS,
        settings.RATE_LIMIT_PAIR_LOCKOUT_SECONDS,
    )
    if pair_result.newly_locked:
        _audit_triggered(db, email, ip, "pair", settings.RATE_LIMIT_PAIR_LOCKOUT_SECONDS)

    if ip:
        ip_result = rate_limit.record_attempt(
            _ip_key(ip), f"{_ip_key(ip)}:lock",
            settings.RATE_LIMIT_IP_WINDOW_SECONDS,
            settings.RATE_LIMIT_IP_MAX_ATTEMPTS,
            settings.RATE_LIMIT_IP_LOCKOUT_SECONDS,
        )
        if ip_result.newly_locked:
            _audit_triggered(db, email, ip, "ip", settings.RATE_LIMIT_IP_LOCKOUT_SECONDS)


def _apply_progressive_escalation(email: str) -> None:
    """Only the account dimension escalates across repeat offenses -- see
    module docstring and RATE_LIMIT_PROGRESSIVE_MULTIPLIER's own comment
    in config.py for why. Called only on the request that just crossed
    the account threshold (`newly_locked`), never on every failed
    attempt.
    """
    strikes = rate_limit.bump_strikes(_strike_key(email), settings.RATE_LIMIT_STRIKE_TTL_SECONDS)
    if strikes <= 1:
        return  # first offense -- base lockout (already applied) stands
    escalated = min(
        settings.RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS * (settings.RATE_LIMIT_PROGRESSIVE_MULTIPLIER ** (strikes - 1)),
        settings.RATE_LIMIT_MAX_LOCKOUT_SECONDS,
    )
    if escalated > settings.RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS:
        rate_limit.set_lock_ttl(f"{_account_key(email)}:lock", escalated)


def _audit_triggered(db: Session, email: str, ip: str, dimension: str, lockout_seconds: int) -> None:
    RATE_LIMIT_DIMENSION_TRIGGERED.labels(dimension=dimension).inc()
    audit_service.log_event(
        db, AuditEventType.AUTH_RATE_LIMIT_TRIGGERED,
        metadata={
            "email": email,
            "ip": ip,
            "dimension": dimension,
            "lockout_seconds": lockout_seconds,
        },
    )


def record_success(email: str, ip: str | None) -> None:
    """Resets the account and (account, IP) counters/locks/strikes on a
    successful login -- a legitimate user who eventually gets their
    password right shouldn't stay throttled. Deliberately does NOT clear
    the IP-wide counter: other accounts may still be under active attack
    from the same (possibly shared/NAT'd) IP, and this login's success
    says nothing about those.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return

    ip = ip or ""
    acct_key = _account_key(email)
    pair_key = _pair_key(email, ip)
    rate_limit.clear(acct_key, f"{acct_key}:lock", _strike_key(email), pair_key, f"{pair_key}:lock")
