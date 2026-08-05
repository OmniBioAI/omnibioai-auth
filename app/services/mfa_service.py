"""PR11.5.2 (Enterprise TOTP MFA Enrollment) + PR11.5.3 (Enterprise MFA
Login Challenge). See docs/pr11-totp-enrollment-discovery.md and
docs/pr11-mfa-login-challenge-discovery.md for the full design
rationale of each half of this module.

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
from app.db.models import MFADevice, RevokedToken, User
from app.services import audit_service, org_service
from app.services.audit_service import AuditEventType
from app.services.auth_service import generate_tokens

_ISSUER = "OmniBioAI"
_DIGITS = 6
_PERIOD = 30
_VERIFY_WINDOW = 1  # +-1 step (~90s total tolerance) for clock drift


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
    correctly so far."""
    if not code or not code.isdigit() or len(code) != _DIGITS:
        return False
    if for_time is None:
        for_time = int(time.time())
    for step in range(-_VERIFY_WINDOW, _VERIFY_WINDOW + 1):
        candidate = _totp_code_at(secret_b32, for_time + step * _PERIOD)
        if hmac.compare_digest(candidate, code):
            return True
    return False


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


def verify_mfa_challenge(db: Session, challenge_token: str, code: str) -> tuple[str, str]:
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
    """
    try:
        payload = decode_token(challenge_token)
    except Exception:
        raise MFAChallengeError("Invalid or expired challenge token")

    if payload.get("type") != "mfa_challenge":
        raise MFAChallengeError("Invalid or expired challenge token")

    jti = payload.get("jti")
    if jti and db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first():
        raise MFAChallengeError("Invalid or expired challenge token")

    user_id = payload.get("user_id")
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
        secret = crypto.decrypt(device.encrypted_secret)
        if verify_totp_code(secret, code):
            matched_device = device
            break

    org_membership = org_service.resolve_primary_membership(db, user.id)
    organization_id = org_membership.organization_id if org_membership else None
    auth_method = payload.get("auth_method") or "password"

    if matched_device is None:
        audit_service.log_event(
            db, AuditEventType.MFA_VERIFICATION_FAILED,
            actor_user_id=user.id, target_user_id=user.id, organization_id=organization_id,
            resource_type="user", resource_id=user.id,
            metadata={"authentication_method": auth_method},
        )
        raise ValueError("Invalid verification code")

    now = datetime.utcnow()
    matched_device.last_used_at = now
    user.mfa_last_verified_at = now
    # Single-use: the jti is now permanently in revoked_tokens, the same
    # table assert_token_usable already checks for any token type -- a
    # second presentation of this same challenge_token hits the reuse
    # check above and is rejected, defense-in-depth on top of
    # get_current_user's own explicit type=="mfa_challenge" rejection
    # (app/rbac.py) that already keeps it from being usable as an access
    # token regardless.
    if jti:
        db.add(RevokedToken(token_jti=jti))
    db.commit()

    audit_service.log_event(
        db, AuditEventType.MFA_VERIFIED,
        actor_user_id=user.id, target_user_id=user.id, organization_id=organization_id,
        resource_type="mfa_device", resource_id=matched_device.id,
        metadata={"authentication_method": auth_method},
    )

    idp_org_id = payload.get("idp_org_id")
    return generate_tokens(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
