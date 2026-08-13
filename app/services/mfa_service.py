"""PR11.5.2 (Enterprise TOTP MFA Enrollment) + PR11.5.3 (Enterprise MFA
Login Challenge) + PR11.5.4 (Enterprise MFA Recovery Codes + Admin
Reset) + PR11.5.5 (Enterprise Organization MFA Policy). See
docs/pr11-totp-enrollment-discovery.md,
docs/pr11-mfa-login-challenge-discovery.md,
docs/pr11-mfa-recovery-codes-discovery.md, and
docs/pr11-mfa-org-policy-discovery.md for the full design rationale of
each part of this module.

TOTP is implemented directly against the stdlib (RFC 6238 / RFC 4226),
not a third-party library -- see the enrollment discovery doc SS2 for
why. Standard choices throughout: SHA1, 6 digits, 30s period -- what
every mainstream authenticator app (Google Authenticator, Authy,
1Password, Microsoft Authenticator) assumes.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from datetime import datetime

from sqlalchemy.orm import Session

from app.core import crypto
from app.core.jwt import decode_token
from app.db.models import MFADevice, MFARecoveryCode, MFAUsedTOTPStep, OrganizationMFAPolicy, RevokedToken, User
from app.services import audit_service, mfa_throttle_service, org_service
from app.services.audit_service import AuditEventType
from app.services.auth_service import generate_tokens

_ISSUER = "OmniBioAI"
_DIGITS = 6
_PERIOD = 30
_VERIFY_WINDOW = 1  # +-1 step (~90s total tolerance) for clock drift

# PR11.5.4: no I/O -- avoids 1/0 confusion when hand-typed from a
# printed sheet. See docs/pr11-mfa-recovery-codes-discovery.md SS5.
_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_RECOVERY_CODE_GROUP_LEN = 4
_RECOVERY_CODE_GROUPS = 3
_RECOVERY_CODE_COUNT = 10


# ---------------------------------------------------------------------------
# RFC 6238 TOTP primitives -- no persistence, no I/O, pure functions.
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """160 bits (20 bytes), base32-encoded -- the width Google
    Authenticator and most TOTP implementations use, well above RFC
    4226's 128-bit minimum."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _totp_code_at(secret_b32: str, for_time: int) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = int(for_time // _PERIOD)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset:offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    return str(code_int % (10 ** _DIGITS)).zfill(_DIGITS)


def verify_totp_code(secret_b32: str, code: str, for_time: int | None = None) -> bool:
    """Constant-time comparison (hmac.compare_digest) against each
    candidate in the +-1 step window -- this PR's own "constant-time
    verification comparison" requirement, preventing a timing
    side-channel from leaking how many digits an attacker has guessed
    correctly so far.

    Boolean-only: does not identify *which* step matched, so a caller
    cannot enforce single-use redemption of that step from this
    function's result alone. Still used unmodified by TOTP *enrollment*
    (verify_totp_enrollment below), which has no replay exposure of its
    own (a device's own verified_at/disabled_at state already makes a
    second enrollment-confirmation attempt a no-op, see that function's
    docstring). The MFA login challenge path
    (verify_mfa_challenge below) uses _totp_matched_step instead -- see
    docs/security-mfa-totp-replay-protection.md."""
    if not code or not code.isdigit() or len(code) != _DIGITS:
        return False
    if for_time is None:
        for_time = int(time.time())
    for step in range(-_VERIFY_WINDOW, _VERIFY_WINDOW + 1):
        candidate = _totp_code_at(secret_b32, for_time + step * _PERIOD)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def _totp_matched_step(secret_b32: str, code: str, for_time: int | None = None) -> int | None:
    """HIPAA Phase 3b: same window/candidate-generation/constant-time-
    comparison semantics as verify_totp_code above -- clock-skew handling
    is completely unchanged -- but returns the RFC 6238 counter
    (`candidate_time // _PERIOD`) that actually matched, instead of a
    bare boolean, so a caller can atomically claim single-use redemption
    of that *specific* step (see _try_claim_totp_step and
    verify_mfa_challenge below). Returns None for a malformed or
    non-matching code, exactly where verify_totp_code would return
    False."""
    if not code or not code.isdigit() or len(code) != _DIGITS:
        return None
    if for_time is None:
        for_time = int(time.time())
    for step in range(-_VERIFY_WINDOW, _VERIFY_WINDOW + 1):
        candidate_time = for_time + step * _PERIOD
        candidate = _totp_code_at(secret_b32, candidate_time)
        if hmac.compare_digest(candidate, code):
            return int(candidate_time // _PERIOD)
    return None


def generate_provisioning_uri(secret_b32: str, account_email: str) -> str:
    label = urllib.parse.quote(f"{_ISSUER}:{account_email}")
    params = urllib.parse.urlencode({
        "secret": secret_b32,
        "issuer": _ISSUER,
        "algorithm": "SHA1",
        "digits": _DIGITS,
        "period": _PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Enrollment. Every mutation + audit call lives here, never in
# routes_mfa.py -- same convention apikey_service.py/oauth_client_service.py
# already establish.
# ---------------------------------------------------------------------------


def _disable_pending_totp_devices(db: Session, user_id: int) -> None:
    """Soft-disables any of this user's existing pending (unverified,
    not yet disabled) TOTP devices before a new enrollment starts -- so
    re-scanning a fresh QR code replaces an abandoned attempt rather than
    accumulating dead pending rows. An abandoned pending device grants no
    access regardless (mfa_enabled only flips on a *verified* device),
    so this is about hygiene, not closing a security hole."""
    pending = (
        db.query(MFADevice)
        .filter(
            MFADevice.user_id == user_id,
            MFADevice.device_type == "totp",
            MFADevice.verified_at.is_(None),
            MFADevice.disabled_at.is_(None),
        )
        .all()
    )
    if not pending:
        return
    now = datetime.utcnow()
    for device in pending:
        device.disabled_at = now
    db.commit()


def start_totp_enrollment(db: Session, user_id: int, account_email: str) -> tuple[MFADevice, str]:
    """Returns (MFADevice row, otpauth_uri). The plaintext secret exists
    only for the duration of this call -- encrypted before the row is
    ever constructed, used once more to build the URI, then out of
    scope. Never logged, never in audit metadata, never persisted.
    Does NOT mark the user as MFA-enabled -- that only happens on
    successful verification.
    """
    _disable_pending_totp_devices(db, user_id)

    secret = generate_totp_secret()
    device = MFADevice(
        user_id=user_id,
        device_type="totp",
        label=None,
        encrypted_secret=crypto.encrypt(secret),
        created_at=datetime.utcnow(),
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    # Never include the secret or the derived URI -- device_type only.
    audit_service.log_event(
        db, AuditEventType.MFA_DEVICE_ENROLLMENT_STARTED,
        actor_user_id=user_id, target_user_id=user_id,
        resource_type="mfa_device", resource_id=device.id,
        metadata={"device_type": device.device_type},
    )

    uri = generate_provisioning_uri(secret, account_email)
    return device, uri


def verify_totp_enrollment(db: Session, user_id: int, device_id: int, code: str) -> MFADevice:
    """Raises LookupError if no such pending device belongs to this user
    (translated to 404 by the route -- never confirms whether a device
    id belonging to someone else exists, same reasoning as
    get_org_membership's 404-not-403 for org ids). Raises ValueError for
    an already-verified/disabled device or an invalid code (translated
    to 400)."""
    device = (
        db.query(MFADevice)
        .filter(MFADevice.id == device_id, MFADevice.user_id == user_id)
        .first()
    )
    if device is None:
        raise LookupError("MFA device not found")
    if device.disabled_at is not None:
        raise ValueError("This enrollment is no longer active -- start a new one")
    if device.verified_at is not None:
        raise ValueError("This device is already verified")

    secret = crypto.decrypt(device.encrypted_secret)
    if not verify_totp_code(secret, code):
        raise ValueError("Invalid verification code")

    now = datetime.utcnow()
    device.verified_at = now
    db.commit()
    db.refresh(device)

    audit_service.log_event(
        db, AuditEventType.MFA_DEVICE_ADDED,
        actor_user_id=user_id, target_user_id=user_id,
        resource_type="mfa_device", resource_id=device.id,
        after_state={"device_type": device.device_type, "verified": True},
        metadata={"device_type": device.device_type},
    )

    user = db.query(User).filter(User.id == user_id).first()
    was_enabled = bool(user.mfa_enabled)
    user.mfa_enabled = True
    user.mfa_status = "enabled"
    user.mfa_primary_method = "totp"
    user.mfa_enabled_at = now
    user.mfa_last_verified_at = now
    db.commit()

    # Don't log a no-op: only emitted when mfa_enabled actually flips
    # False -> True, same convention org_sso_service.set_enforced already
    # uses -- verifying a *second* device while already enabled doesn't
    # re-fire this event (MFA_DEVICE_ADDED above already covers that).
    if not was_enabled:
        audit_service.log_event(
            db, AuditEventType.MFA_ENABLED,
            actor_user_id=user_id, target_user_id=user_id,
            resource_type="user", resource_id=user_id,
            after_state={"mfa_enabled": True, "mfa_primary_method": "totp"},
        )

    return device


# ---------------------------------------------------------------------------
# Device management.
# ---------------------------------------------------------------------------


def list_devices(db: Session, user_id: int) -> list[MFADevice]:
    """Both pending and verified, non-disabled devices -- verified_at
    being null in the response is how a caller distinguishes
    "still awaiting verification" from "active"."""
    return (
        db.query(MFADevice)
        .filter(MFADevice.user_id == user_id, MFADevice.disabled_at.is_(None))
        .order_by(MFADevice.created_at.desc())
        .all()
    )


def remove_device(db: Session, user_id: int, device_id: int) -> None:
    """Soft-remove (disabled_at = now()), never a SQL delete -- the same
    shape apikey_service.revoke_api_key already uses for its own
    DELETE-verbed route (app/api/routes_apikeys.py), so an AuditEvent's
    resource_id keeps a resolvable history instead of pointing at a
    vanished row. Raises LookupError if the device doesn't belong to
    this user (-> 404, never revealing whether a different user's device
    id exists)."""
    device = (
        db.query(MFADevice)
        .filter(
            MFADevice.id == device_id,
            MFADevice.user_id == user_id,
            MFADevice.disabled_at.is_(None),
        )
        .first()
    )
    if device is None:
        raise LookupError("MFA device not found")

    was_verified = device.verified_at is not None
    device.disabled_at = datetime.utcnow()
    db.commit()

    audit_service.log_event(
        db, AuditEventType.MFA_DEVICE_REMOVED,
        actor_user_id=user_id, target_user_id=user_id,
        resource_type="mfa_device", resource_id=device.id,
        before_state={"device_type": device.device_type, "verified": was_verified},
        metadata={"device_type": device.device_type},
    )

    remaining_verified = (
        db.query(MFADevice)
        .filter(
            MFADevice.user_id == user_id,
            MFADevice.verified_at.isnot(None),
            MFADevice.disabled_at.is_(None),
        )
        .count()
    )
    if remaining_verified == 0:
        user = db.query(User).filter(User.id == user_id).first()
        if user.mfa_enabled:
            user.mfa_enabled = False
            user.mfa_status = "disabled"
            db.commit()
            # Don't log a no-op: only when this removal actually flipped
            # mfa_enabled True -> False (e.g. removing an already-inert
            # pending device, or a non-last verified device, must not
            # fire this).
            audit_service.log_event(
                db, AuditEventType.MFA_DISABLED,
                actor_user_id=user_id, target_user_id=user_id,
                resource_type="user", resource_id=user_id,
                after_state={"mfa_enabled": False},
            )


# ---------------------------------------------------------------------------
# PR11.5.3 (Enterprise MFA Login Challenge). See
# docs/pr11-mfa-login-challenge-discovery.md SS8 for the full design.
# ---------------------------------------------------------------------------


class MFAChallengeError(ValueError):
    """Raised for anything wrong with the *challenge token itself* --
    malformed, expired, wrong type, already used, or belonging to a
    user who is no longer active or no longer has MFA enabled.
    Deliberately one generic message across all of these (see
    verify_mfa_challenge's own docstring) -- always mapped to 401 by
    the route. A plain ValueError (not this subclass) means the token
    was fine but the *code* was wrong -- mapped to 400 instead."""


class MFAThrottledError(Exception):
    """HIPAA Phase 3: raised when mfa_throttle_service reports the
    account/IP/(account, IP) pair behind this request is currently locked
    out. Mapped to 429 by the route, mirroring
    login_throttle_service/routes_auth.py's own `throttle.locked` ->
    429-with-Retry-After shape. A distinct exception, not MFAChallengeError
    reused, so the route can tell "throttled" apart from "bad token" and
    attach the right Retry-After -- both still reveal nothing about the
    account beyond what the existing 401/400 responses already do."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Too many MFA verification attempts")


def _try_claim_totp_step(db: Session, device_id: int, time_step: int) -> bool:
    """HIPAA Phase 3b: attempts to atomically claim single-use redemption
    of `time_step` for `device_id` by inserting a row into
    `mfa_used_totp_steps` and committing. Returns True only for the one
    caller whose commit actually lands first -- `UNIQUE(device_id,
    time_step)` (app/db/models.py::MFAUsedTOTPStep) is what provides the
    atomicity, correct across any number of horizontally-scaled instances
    sharing this database, not any Python-level lock. Returns False for
    every other case: the step was already claimed by an earlier or
    concurrent request (the expected, common "this exact code was already
    used" replay rejection), or the insert/commit failed for any other
    reason (a transient DB error, say) -- deliberately fails *closed*
    here: this function's only job is proving a step hasn't been used
    before, so any outcome short of a clean, confirmed claim must be
    treated as "cannot confirm this is fresh, therefore reject," never as
    "silently allow it through." See
    docs/security-mfa-totp-replay-protection.md.

    Always leaves `db` in a clean, usable state for whatever the caller
    does next (rollback on the failure path) -- the caller's own
    subsequent queries (recovery-code fallback, audit logging) must not
    inherit a half-failed transaction from this attempt.
    """
    try:
        db.add(MFAUsedTOTPStep(device_id=device_id, time_step=time_step))
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def verify_mfa_challenge(db: Session, challenge_token: str, code: str, client_ip: str | None = None) -> tuple[str, str]:
    """Completes an MFA-gated login. Validates `challenge_token` (issued
    by auth_service.generate_tokens_or_mfa_challenge), verifies `code`
    against every verified TOTP device the user holds -- not just one,
    multiple verified devices are supported since PR11.5.1/PR11.5.2 --
    and on success calls the existing, unchanged generate_tokens to
    finish the login exactly as primary auth would have, had MFA not
    been required.

    Raises MFAChallengeError (-> 401) for any problem with the token
    itself -- deliberately the same generic message regardless of which
    of malformed/expired/wrong-type/reused/inactive-user/MFA-no-longer-
    enabled applied, so a probing caller learns nothing about *why* a
    given token/user doesn't check out. Raises plain ValueError (-> 400)
    only when the token checks out fine but `code` doesn't match any
    verified device.

    HIPAA Phase 3: raises MFAThrottledError (-> 429) when
    mfa_throttle_service reports this user_id/IP/pair is currently locked
    out of MFA verification -- see app/services/mfa_throttle_service.py
    and docs/security-mfa-challenge-throttling.md for the full design.
    The throttle check runs as early as possible: right after the token's
    signature is verified and its `user_id` claim extracted (a value this
    function already trusts completely -- it's what scopes the rest of
    this function's own logic to one user), but before the RevokedToken/
    user-active/mfa-enabled checks, the device query, any TOTP secret
    decryption, or any recovery-code lookup. This means once an account
    is throttled, *every* challenge request against it gets a uniform 429
    -- including a request whose token would otherwise separately fail
    with 401 -- deliberately mirroring login_throttle_service's own
    "an already-locked account rejects even the correct credential"
    behavior (test_account_lockout_blocks_even_the_correct_password in
    tests/test_login_rate_limiting.py), not a gap.

    A single HTTP request to this function records at most one throttle
    failure, on its one terminal failure branch (both the TOTP-device
    loop and the recovery-code check found no match) -- never per-device,
    never for a request that never got past the token-validity checks
    above (a different failure class, see mfa_throttle_service.record_failure's
    own docstring for why those aren't counted as MFA-guessing attempts).
    An unexpected exception while checking a device's TOTP secret or a
    recovery code (e.g. a corrupted encrypted_secret) is treated as a
    non-match for that candidate rather than allowed to escape and skip
    the throttle counter entirely -- HIPAA Phase 3's own "exceptions
    during verification cannot bypass the throttle" requirement.

    HIPAA Phase 3b: a code that is cryptographically valid but whose
    RFC 6238 time-step has already been redeemed (by an earlier request,
    or by a concurrent one that committed first) is treated as a
    non-match too -- see _try_claim_totp_step and
    docs/security-mfa-totp-replay-protection.md. This is a *different*
    single-use guarantee than the challenge_token's own jti consumption
    below: jti consumption stops one challenge_token from being completed
    twice; step consumption stops the same *code* from completing two
    *different* challenge_tokens (e.g. two separate logins) within its
    own ~90s validity window. Recovery-code single-use is enforced by
    the wholly separate `try_consume_recovery_code` mechanism below
    (HIPAA Phase 5) -- same atomic-claim shape, different table/
    predicate, not touched by this TOTP-specific change.
    """
    try:
        payload = decode_token(challenge_token)
    except Exception:
        raise MFAChallengeError("Invalid or expired challenge token")

    if payload.get("type") != "mfa_challenge":
        raise MFAChallengeError("Invalid or expired challenge token")

    jti = payload.get("jti")
    user_id = payload.get("user_id")

    # HIPAA Phase 3: earliest point a trusted account identifier exists
    # (the token's signature is already verified above) -- checked before
    # any further DB/crypto work. See this function's own docstring for
    # the full ordering rationale.
    if user_id is not None:
        throttle = mfa_throttle_service.check_throttled(user_id, client_ip)
        if throttle.locked:
            raise MFAThrottledError(throttle.retry_after_seconds)

    if jti and db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first():
        raise MFAChallengeError("Invalid or expired challenge token")

    user = db.query(User).filter(User.id == user_id).first() if user_id is not None else None
    if not user or user.status != "active":
        raise MFAChallengeError("Invalid or expired challenge token")

    # Re-checked here, not just at issuance time -- a user who disables
    # MFA (removes their last verified device, see remove_device above)
    # between requesting and completing a challenge must not be able to
    # finish logging in on a now-stale challenge token.
    if not user.mfa_enabled:
        raise MFAChallengeError("Invalid or expired challenge token")

    devices = (
        db.query(MFADevice)
        .filter(
            MFADevice.user_id == user.id,
            MFADevice.verified_at.isnot(None),
            MFADevice.disabled_at.is_(None),
        )
        .all()
    )

    matched_device = None
    for device in devices:
        try:
            secret = crypto.decrypt(device.encrypted_secret)
            step = _totp_matched_step(secret, code)
            # HIPAA Phase 3b: cryptographically correct is not enough --
            # only a *fresh* (never-before-claimed) step counts as a real
            # match. _try_claim_totp_step's UNIQUE(device_id, time_step)
            # insert is what rejects a replayed code (whether from a
            # captured/intercepted code, a duplicated request, or two
            # literally concurrent requests racing on the same code) --
            # a code that's cryptographically right but whose step was
            # already claimed falls through exactly like a wrong code,
            # never distinguished in the response. See
            # docs/security-mfa-totp-replay-protection.md.
            if step is not None and _try_claim_totp_step(db, device.id, step):
                matched_device = device
                break
        except Exception:
            # HIPAA Phase 3: a broken/undecryptable device must not 500
            # this request (and, more importantly, must not let it skip
            # the throttle counter below by raising past it) -- treated
            # as "this device doesn't match", the same outcome as a wrong
            # code, and verification continues against any other device.
            continue

    org_membership = org_service.resolve_primary_membership(db, user.id)
    organization_id = org_membership.organization_id if org_membership else None
    auth_method = payload.get("auth_method") or "password"
    idp_org_id = payload.get("idp_org_id")
    # PR11 (SLO): carried through from create_mfa_challenge_token -- None
    # for every non-SAML challenge token, unaffected. See that
    # function's own docstring for why a SAML+personal-MFA login needs
    # this threaded through the challenge round trip at all.
    saml_name_id = payload.get("saml_name_id")
    saml_session_index = payload.get("saml_session_index")
    organization_saml_config_id = payload.get("organization_saml_config_id")

    if matched_device is not None:
        now = datetime.utcnow()
        matched_device.last_used_at = now
        user.mfa_last_verified_at = now
        _consume_challenge_jti(db, jti)
        mfa_throttle_service.record_success(user_id, client_ip)

        audit_service.log_event(
            db, AuditEventType.MFA_VERIFIED,
            actor_user_id=user.id, target_user_id=user.id, organization_id=organization_id,
            resource_type="mfa_device", resource_id=matched_device.id,
            metadata={"authentication_method": auth_method},
        )
        return generate_tokens(
            db, user, auth_method=auth_method, idp_org_id=idp_org_id,
            saml_name_id=saml_name_id, saml_session_index=saml_session_index,
            organization_saml_config_id=organization_saml_config_id,
        )

    # PR11.5.4: TOTP didn't match any device -- try `code` as a recovery
    # code before giving up. Same challenge_token, same request shape;
    # the code's own format (6 digits vs "AAAA-BBBB-CCCC") is what
    # disambiguates, never a separate endpoint or field. See
    # docs/pr11-mfa-recovery-codes-discovery.md SS3.
    try:
        recovery_match = verify_recovery_code(db, user.id, code)
    except Exception:
        # Same "treat as no-match, never let the throttle be bypassed by
        # an unexpected error" reasoning as the TOTP loop above.
        recovery_match = None
    # HIPAA Phase 5: cryptographically/hash-correct is not enough here
    # either -- same "match, then atomically claim" shape as the TOTP
    # loop above. try_consume_recovery_code's own UPDATE ... WHERE
    # used_at IS NULL is what rejects a genuinely concurrent duplicate
    # (two different challenge_tokens racing to redeem the same code) --
    # a code that verify_recovery_code found but whose claim is lost
    # falls through exactly like a wrong code, never distinguished in
    # the response. See docs/security-mfa-recovery-code-atomicity.md.
    if recovery_match is not None and try_consume_recovery_code(db, recovery_match.id):
        now = datetime.utcnow()
        user.mfa_last_verified_at = now
        _consume_challenge_jti(db, jti)
        mfa_throttle_service.record_success(user_id, client_ip)

        audit_service.log_event(
            db, AuditEventType.MFA_RECOVERY_CODE_USED,
            actor_user_id=user.id, target_user_id=user.id, organization_id=organization_id,
            resource_type="user", resource_id=user.id,
            metadata={"authentication_method": auth_method},
        )
        return generate_tokens(
            db, user, auth_method=auth_method, idp_org_id=idp_org_id,
            saml_name_id=saml_name_id, saml_session_index=saml_session_index,
            organization_saml_config_id=organization_saml_config_id,
        )

    # HIPAA Phase 3: the one terminal failure branch -- exactly one
    # record_failure call per request, regardless of how many devices
    # were checked above. Must run before the ValueError below, not in a
    # caller-side except block, since a plain ValueError is also how
    # every *other* "code didn't match" case in this codebase already
    # signals -- catching it generically at the route layer would risk
    # conflating this with an unrelated future ValueError.
    mfa_throttle_service.record_failure(db, user_id, client_ip, organization_id)

    audit_service.log_event(
        db, AuditEventType.MFA_VERIFICATION_FAILED,
        actor_user_id=user.id, target_user_id=user.id, organization_id=organization_id,
        resource_type="user", resource_id=user.id,
        metadata={"authentication_method": auth_method},
    )
    raise ValueError("Invalid verification code")


def _consume_challenge_jti(db: Session, jti: str | None) -> None:
    """Single-use enforcement, shared by both the TOTP and recovery-code
    success paths above: the jti is now permanently in revoked_tokens,
    the same table assert_token_usable already checks for any token
    type -- a second presentation of this same challenge_token hits the
    reuse check earlier in verify_mfa_challenge and is rejected,
    defense-in-depth on top of get_current_user's own explicit
    type=="mfa_challenge" rejection (app/rbac.py) that already keeps it
    from being usable as an access token regardless.

    HIPAA Phase 3b: `RevokedToken.token_jti` is UNIQUE
    (app/db/models.py), so this INSERT is also a backstop that
    guarantees exactly one winner when two concurrent requests both
    reach this point for the *same* challenge_token -- both the TOTP path
    (`_try_claim_totp_step`) and the recovery-code path
    (`try_consume_recovery_code`, HIPAA Phase 5) already make that
    same-token race effectively unreachable on their own, at the point
    each one claims its own resource, so in practice this now mostly
    guards against the same challenge_token being raced by two requests
    where *neither* code path's own claim was ever contested (e.g. a
    plain duplicated/retried HTTP request presenting the exact same
    already-correct code twice). Kept as defense-in-depth regardless --
    still caught and re-raised as MFAChallengeError (-> 401, same shape
    the reuse check earlier in verify_mfa_challenge already uses for a
    stale/already-consumed token) rather than left as an unhandled 500,
    and since this INSERT shares its caller's not-yet-committed pending
    changes (matched_device/user.mfa_last_verified_at updates), the
    rollback below cleanly discards those too, leaving no partial state
    behind for the losing request. Still exactly one session is ever
    minted per challenge_token, regardless of which path raced to get
    here.
    """
    if not jti:
        db.commit()
        return
    try:
        db.add(RevokedToken(token_jti=jti))
        db.commit()
    except Exception:
        db.rollback()
        raise MFAChallengeError("Invalid or expired challenge token")


# ---------------------------------------------------------------------------
# PR11.5.4 (Enterprise MFA Recovery Codes + Admin Reset). See
# docs/pr11-mfa-recovery-codes-discovery.md for the full design.
# ---------------------------------------------------------------------------


def _generate_one_recovery_code() -> str:
    groups = [
        "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(_RECOVERY_CODE_GROUP_LEN))
        for _ in range(_RECOVERY_CODE_GROUPS)
    ]
    return "-".join(groups)


def _hash_recovery_code(code: str) -> str:
    # Normalize case/whitespace -- a user re-typing a code from a
    # printed sheet may vary casing/spacing; the hyphens are part of the
    # canonical displayed format and hashed as-is, matching exactly what
    # was generated and shown.
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def invalidate_recovery_codes(db: Session, user_id: int) -> int:
    """Marks every currently-unused recovery code for this user as used
    -- MFARecoveryCode has no separate disabled_at column (and none is
    added by this PR); reusing `used_at` as a general "no longer
    redeemable" marker is deliberate, see the discovery doc SS1. Called
    by regenerate_recovery_codes (before issuing a fresh batch) and by
    reset_user_mfa (admin reset). Returns the number of codes
    invalidated, for the caller's own audit metadata -- purely
    informational, the invalidation itself has already happened by the
    time this returns. No audit event of its own: both callers already
    emit a more specific event that captures *why*."""
    now = datetime.utcnow()
    unused = (
        db.query(MFARecoveryCode)
        .filter(MFARecoveryCode.user_id == user_id, MFARecoveryCode.used_at.is_(None))
        .all()
    )
    for row in unused:
        row.used_at = now
    if unused:
        db.commit()
    return len(unused)


def _issue_recovery_codes(db: Session, user_id: int, event_type: str) -> list[str]:
    invalidated = invalidate_recovery_codes(db, user_id)

    plaintext_codes = [_generate_one_recovery_code() for _ in range(_RECOVERY_CODE_COUNT)]
    now = datetime.utcnow()
    for code in plaintext_codes:
        db.add(MFARecoveryCode(user_id=user_id, code_hash=_hash_recovery_code(code), created_at=now))
    db.commit()

    audit_service.log_event(
        db, event_type, actor_user_id=user_id, target_user_id=user_id,
        resource_type="user", resource_id=user_id,
        metadata={"codes_issued": len(plaintext_codes), "codes_invalidated": invalidated},
    )
    return plaintext_codes


def generate_recovery_codes(db: Session, user_id: int) -> list[str]:
    """Generates 10 new recovery codes. Always invalidates any existing
    unused codes first (via invalidate_recovery_codes) so a user can
    never end up with two live batches at once -- safe to call
    unconditionally, including a second time for a user who already has
    an unused batch. Returns the plaintext codes -- the only moment they
    exist outside this function; only their SHA-256 hash is ever
    persisted."""
    return _issue_recovery_codes(db, user_id, AuditEventType.MFA_RECOVERY_CODES_GENERATED)


def regenerate_recovery_codes(db: Session, user_id: int) -> list[str]:
    """Same underlying operation as generate_recovery_codes (invalidate
    old, issue new 10) -- distinguished only by which audit event fires.
    POST /users/me/mfa/recovery-codes/regenerate is a distinct, explicit
    user action worth its own event type
    (MFA_RECOVERY_CODES_REGENERATED)."""
    return _issue_recovery_codes(db, user_id, AuditEventType.MFA_RECOVERY_CODES_REGENERATED)


def recovery_codes_remaining(db: Session, user_id: int) -> int:
    return (
        db.query(MFARecoveryCode)
        .filter(MFARecoveryCode.user_id == user_id, MFARecoveryCode.used_at.is_(None))
        .count()
    )


def verify_recovery_code(db: Session, user_id: int, code: str) -> MFARecoveryCode | None:
    """Returns the matching, still-unused row for this user, or None.
    Comparison is a direct hash-equality lookup, not
    hmac.compare_digest -- unlike TOTP's 6-digit code (short, guessable
    digit-by-digit, so a timing side-channel on the comparison matters),
    the value compared here is already an irreversible SHA-256 digest,
    not the secret itself; there is no analogous incremental-guessing
    shape to defend against. See the discovery doc SS5 for the full
    reasoning."""
    if not code:
        return None
    code_hash = _hash_recovery_code(code)
    return (
        db.query(MFARecoveryCode)
        .filter(
            MFARecoveryCode.user_id == user_id,
            MFARecoveryCode.code_hash == code_hash,
            MFARecoveryCode.used_at.is_(None),
        )
        .first()
    )


def try_consume_recovery_code(db: Session, code_id: int) -> bool:
    """HIPAA Phase 5: atomically claims single-use consumption of the
    MFARecoveryCode row `code_id` -- one UPDATE, with the single-use
    precondition (`used_at IS NULL`) baked into its own WHERE clause,
    not a separate read beforehand. Returns True only for the caller
    whose UPDATE is the one that actually transitions the row from
    unused -> used; False if it was already used (by an earlier request,
    or a genuinely concurrent one whose UPDATE committed first) or no
    such row exists.

    Replaces the old consume_recovery_code, which unconditionally set
    `used_at` with no precondition at all -- verify_recovery_code (still
    unchanged, still a plain read) and the old consume_recovery_code
    together were a classic read-then-write TOCTOU: two concurrent
    requests could each independently see the same row as unused (their
    reads racing before either write), and the old consume had nothing
    to reject a second write with, so both would "succeed". Each request
    in that race carries its own, independently-issued challenge_token
    (a fresh login -> a fresh jti each time) -- `RevokedToken.token_jti`'s
    own UNIQUE constraint, which backstops the analogous same-jti race
    on the *token*, does not apply across two *different* jtis, so it
    could not catch this: two different valid recovery-code-completed
    challenge_tokens meant two independently-mintable sessions from one
    recovery code. Deterministically reproduced against this exact
    pre-fix code during discovery -- see
    docs/security-mfa-recovery-code-atomicity.md.

    The database's own row-level locking during the UPDATE (MySQL/InnoDB
    in production; SQLite's whole-database write lock in tests) is what
    provides the atomicity here -- not any Python-level lock, and correct
    across any number of horizontally-scaled `omnibioai-auth` instances
    sharing this database, the same guarantee
    `_try_claim_totp_step` (HIPAA Phase 3b) already provides for TOTP
    steps and `RevokedToken.token_jti`'s UNIQUE constraint already
    provides for challenge tokens -- same `db.query(...).filter(...).update(...)`
    shape `auth_service._revoke_family` already uses elsewhere in this
    service, applied here with an added precondition instead of an
    unconditional one.

    Commits immediately, independently of the caller's own later
    `_consume_challenge_jti` commit -- deliberately not bundled into one
    transaction with it (same separate-commit shape the old
    consume_recovery_code already had): a recovery code that this call
    genuinely, atomically claimed is spent, permanently, regardless of
    what an unrelated later step in the same request does -- rolling
    that back to make the code available again if a *different*
    single-use check fails afterward for an unrelated reason would
    reopen exactly the kind of "is this code still valid" ambiguity this
    fix exists to close, and is deliberately out of this fix's scope.

    No audit event here -- the caller (verify_mfa_challenge) owns the
    actual MFA_RECOVERY_CODE_USED event, only ever emitted once this
    function has already returned True, so a lost race never emits one.
    """
    claimed = (
        db.query(MFARecoveryCode)
        .filter(MFARecoveryCode.id == code_id, MFARecoveryCode.used_at.is_(None))
        .update({"used_at": datetime.utcnow()})
    )
    db.commit()
    return claimed == 1


def reset_user_mfa(db: Session, target_user_id: int, actor_user_id: int) -> None:
    """Admin break-glass: fully resets a user's MFA state. Disables
    every device, invalidates every recovery code, and clears the
    user's own mfa_* fields -- but never touches User.status,
    last_login_at, authentication_method, or any AuditEvent row (login
    history and audit history are explicitly preserved). The user can
    freely re-enroll from scratch afterward via the normal PR11.5.2
    enrollment flow. Raises LookupError if target_user_id doesn't exist
    (-> 404, route)."""
    user = db.query(User).filter(User.id == target_user_id).first()
    if user is None:
        raise LookupError("User not found")

    now = datetime.utcnow()
    devices = (
        db.query(MFADevice)
        .filter(MFADevice.user_id == target_user_id, MFADevice.disabled_at.is_(None))
        .all()
    )
    for device in devices:
        device.disabled_at = now

    invalidated_codes = invalidate_recovery_codes(db, target_user_id)

    user.mfa_enabled = False
    user.mfa_status = "disabled"
    user.mfa_primary_method = None
    user.mfa_enabled_at = None
    user.mfa_last_verified_at = None
    db.commit()

    audit_service.log_event(
        db, AuditEventType.MFA_RESET_BY_ADMIN,
        actor_user_id=actor_user_id, target_user_id=target_user_id,
        resource_type="user", resource_id=target_user_id,
        after_state={"mfa_enabled": False, "mfa_status": "disabled"},
        metadata={"devices_disabled": len(devices), "recovery_codes_invalidated": invalidated_codes},
    )


# ---------------------------------------------------------------------------
# PR11.5.5 (Enterprise Organization MFA Policy). See
# docs/pr11-mfa-org-policy-discovery.md for the full design. Deliberately
# kept in this module rather than a new org_mfa_policy_service.py --
# this PR's own deliverables list names app/services/mfa_service.py,
# and every MFA-domain mutation (personal or org-level) now lives in one
# place. No relationship to MFADevice/MFARecoveryCode -- this table only
# ever asks "does this org require MFA."
# ---------------------------------------------------------------------------


def get_org_mfa_policy(db: Session, organization_id: int) -> OrganizationMFAPolicy | None:
    return (
        db.query(OrganizationMFAPolicy)
        .filter(OrganizationMFAPolicy.organization_id == organization_id)
        .first()
    )


def create_org_mfa_policy(
    db: Session, organization_id: int, required: bool, actor_user_id: int
) -> OrganizationMFAPolicy:
    """Raises ValueError if a policy already exists (one per org --
    organization_id is UNIQUE), same shape org_sso_service.configure_sso
    uses for its own "already exists" case."""
    if get_org_mfa_policy(db, organization_id) is not None:
        raise ValueError("this organization already has an MFA policy")

    now = datetime.utcnow()
    policy = OrganizationMFAPolicy(
        organization_id=organization_id,
        required=required,
        created_at=now,
        enabled_at=now if required else None,
        enabled_by_user_id=actor_user_id if required else None,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    if required:
        audit_service.log_event(
            db, AuditEventType.MFA_POLICY_ENABLED, actor_user_id=actor_user_id,
            organization_id=organization_id, resource_type="organization_mfa_policy", resource_id=policy.id,
            before_state={"required": False}, after_state={"required": True},
            metadata={"reason": None},
        )
    return policy


def set_org_mfa_required(
    db: Session, policy: OrganizationMFAPolicy, required: bool, actor_user_id: int, reason: str | None = None,
) -> OrganizationMFAPolicy:
    """Same "don't log a no-op" convention org_sso_service.set_enforced
    already uses -- only emits an event on an actual flip. `reason` is
    optional (unlike the override endpoints below): a routine policy
    toggle doesn't always warrant one, but it's carried into the audit
    event's metadata whenever supplied, satisfying this PR's own "every
    event must contain organization_id/actor_user_id/reason" rule with
    an honest `None` when omitted rather than forcing a value."""
    before_required = policy.required
    policy.required = required
    policy.updated_at = datetime.utcnow()

    if required and not before_required:
        policy.enabled_at = datetime.utcnow()
        policy.enabled_by_user_id = actor_user_id

    db.commit()
    db.refresh(policy)

    if before_required != required:
        event_type = AuditEventType.MFA_POLICY_ENABLED if required else AuditEventType.MFA_POLICY_DISABLED
        audit_service.log_event(
            db, event_type, actor_user_id=actor_user_id,
            organization_id=policy.organization_id, resource_type="organization_mfa_policy", resource_id=policy.id,
            before_state={"required": before_required}, after_state={"required": required},
            metadata={"reason": reason},
        )
    return policy


def set_org_mfa_override(
    db: Session, policy: OrganizationMFAPolicy, reason: str, actor_user_id: int,
) -> OrganizationMFAPolicy:
    """Global-admin break-glass bypass: suspends the *effect* of
    `required` for this org without changing `required` itself, so the
    org's own configured intent is preserved and resumes automatically
    once the override is cleared. Does NOT touch any User.mfa_enabled
    value or any user's own enrolled devices/recovery codes -- see
    docs/pr11-mfa-org-policy-discovery.md SS3 for why personal MFA is
    unaffected by an org-level override. Deliberately overwrites any
    prior override (re-triggering it just updates who/why/when, not an
    error) -- idempotent from the caller's perspective, same as
    org_sso_service.set_sso_override."""
    was_active = policy.override_active
    now = datetime.utcnow()
    policy.override_active = True
    policy.override_reason = reason
    policy.override_at = now
    policy.override_by_user_id = actor_user_id
    db.commit()
    db.refresh(policy)

    audit_service.log_event(
        db, AuditEventType.MFA_POLICY_OVERRIDE_CREATED, actor_user_id=actor_user_id,
        organization_id=policy.organization_id, resource_type="organization_mfa_policy", resource_id=policy.id,
        before_state={"override_active": was_active, "required": policy.required},
        after_state={"override_active": True, "required": policy.required},
        metadata={"reason": reason},
    )
    return policy


def clear_org_mfa_override(
    db: Session, policy: OrganizationMFAPolicy, actor_user_id: int,
) -> OrganizationMFAPolicy:
    """Only emits an event if an override was actually active before
    clearing -- same no-op-avoidance convention as
    org_sso_service.clear_sso_override. `reason` in the removal event's
    metadata is the *outgoing* override's own reason (why it existed),
    giving the removal event context without requiring a request body
    on this DELETE endpoint."""
    was_active = policy.override_active
    before_reason = policy.override_reason
    before_by_user_id = policy.override_by_user_id

    policy.override_active = False
    policy.override_reason = None
    policy.override_at = None
    policy.override_by_user_id = None
    db.commit()
    db.refresh(policy)

    if was_active:
        audit_service.log_event(
            db, AuditEventType.MFA_POLICY_OVERRIDE_REMOVED, actor_user_id=actor_user_id,
            organization_id=policy.organization_id, resource_type="organization_mfa_policy", resource_id=policy.id,
            before_state={
                "override_active": True, "override_reason": before_reason,
                "override_by_user_id": before_by_user_id,
            },
            after_state={"override_active": False},
            metadata={"reason": before_reason},
        )
    return policy
