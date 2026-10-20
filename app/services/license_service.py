"""
OmniBioAI app.services.license_service.

Purpose:
    Defines generate_key, create_license, get_or_create_user_for_email and validate_and_consume for app.services.license_service.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import hashlib
import hmac
import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from app.core.config import settings
from app.db.models import LicenseKey, User
from app.services.role_service import assign_default_role

# Excludes visually ambiguous characters (0/O, 1/I/L) since keys are
# read off a screen and typed by hand on first launch.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_GROUP_LEN = 4
_GROUP_COUNT = 4


def generate_key() -> str:
    groups = [
        "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN))
        for _ in range(_GROUP_COUNT)
    ]
    return "OMNI-" + "-".join(groups)


def normalize_key(key: str) -> str:
    return key.strip().upper()


def utc_now() -> datetime:
    """Return UTC as a naive datetime for the existing DATETIME columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def digest_key(key: str) -> str:
    """One-way verifier for new keys; deliberately independent of JWT keys."""
    if not settings.LICENSE_KEY_PEPPER:
        raise RuntimeError("LICENSE_KEY_PEPPER is required for new license issuance")
    return hmac.new(
        settings.LICENSE_KEY_PEPPER.encode("utf-8"),
        normalize_key(key).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def lookup_license(db, key: str, *, lock: bool = False) -> LicenseKey | None:
    """Resolve digest-only new keys first, then untouched plaintext legacy rows."""
    normalized = normalize_key(key)
    query = db.query(LicenseKey)
    if lock:
        query = query.with_for_update()
    if settings.LICENSE_KEY_PEPPER:
        found = query.filter(LicenseKey.key_digest == digest_key(normalized)).first()
        if found:
            return found
    # Compatibility path only. New issuance always leaves `key` NULL.
    return query.filter(LicenseKey.key == normalized, LicenseKey.key_digest.is_(None)).first()


def is_legacy_plaintext(license_key: LicenseKey) -> bool:
    return license_key.key_digest is None and license_key.key is not None


def masked_key(license_key: LicenseKey) -> str:
    prefix = license_key.key_prefix or ((license_key.key or "")[:9]) or "OMNI"
    return f"{prefix}-••••-••••-••••"


def create_license(
    db,
    email: str,
    user_id: int,
    organization_id: int | None,
    plan: str = "beta",
    platform: str = "both",
    expires_days: int | None = None,
    max_uses: int = 1,
    recipient_name: str | None = None,
    commit: bool = True,
) -> LicenseKey:
    key = generate_key()
    # Astronomically unlikely, but a live service shouldn't silently accept
    # a collision — regenerate rather than fail the caller's request.
    key_digest = digest_key(key)
    while db.query(LicenseKey).filter(LicenseKey.key_digest == key_digest).first():
        key = generate_key()
        key_digest = digest_key(key)

    license_key = LicenseKey(
        key=None,
        key_digest=key_digest,
        key_prefix=key[:9],
        email=email,
        recipient_name=recipient_name,
        user_id=user_id,
        organization_id=organization_id,
        plan=plan,
        platform=platform,
        max_uses=max_uses,
        expires_at=(
            utc_now() + timedelta(days=expires_days)
            if expires_days is not None
            else None
        ),
    )
    db.add(license_key)
    db.flush()
    # Process-memory-only handoff to the route for the first response. This
    # attribute is neither mapped nor persisted and is never available later.
    license_key._one_time_key = key
    if commit:
        db.commit()
        db.refresh(license_key)
    return license_key


def get_or_create_user_for_email(db, email: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        return user
    # License-only signup: no password set, same shape as an OAuth-only
    # account created via the SSO flow in oauth_service.
    user = User(email=email, hashed_password=None, status="active")
    db.add(user)
    db.flush()
    assign_default_role(db, user)
    return user


def validate_and_consume(
    db, key: str, email: str | None, platform: str
) -> tuple[LicenseKey | None, str | None]:
    """Returns (license, None) on success or (None, reason) on failure.
    Does not commit the caller's User creation -- callers own the transaction.

    email=None skips the email-match check entirely -- the Electron
    key-only activation path (Phase 1 PR4). The web redemption flow always
    passes its collected email and keeps the exact-match check.
    """
    license_key = lookup_license(db, key)
    if not license_key:
        return None, "invalid_key"

    if license_key.revoked_at is not None:
        return None, "revoked"

    if license_key.expires_at is not None and license_key.expires_at <= utc_now():
        return None, "expired"

    # Only a license that has never been successfully activated is subject
    # to the activation-count gate. Once bound, every later call here is a
    # sign-in by that same already-authorized owner, not a new activation --
    # gating it on usage_count would eventually lock out the one legitimate
    # user a single-user-per-license row is ever bound to (see LicenseKey.
    # user_id's own comment: bound once, on first successful validate, and
    # never rebound).
    if license_key.user_id is None and license_key.usage_count >= license_key.max_uses:
        return None, "usage_exhausted"

    if license_key.platform != "both" and license_key.platform != platform:
        return None, "platform_mismatch"

    if email is not None and license_key.email != email:
        return None, "email_mismatch"

    return license_key, None


def authorize_for_identity(
    db,
    key: str,
    user: User,
    platform: str,
) -> tuple[LicenseKey | None, str | None]:
    """Validate a license and prove it belongs to the authenticated user.

    Raw-key possession is never identity.  Existing bound licenses require
    an exact user_id match.  A legacy unbound license may be claimed only by
    the authenticated account whose canonical email exactly matches; the
    route commits that first bind through mark_used.  Organization-bound
    licenses additionally require an active membership in that organization.
    """
    license_key, reason = validate_and_consume(db, key, user.email, platform)
    if license_key is None:
        return None, reason
    if license_key.user_id is not None and license_key.user_id != user.id:
        return None, "owner_mismatch"
    if license_key.organization_id is not None:
        from app.db.models import OrganizationMembership
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.organization_id == license_key.organization_id,
            OrganizationMembership.status == "active",
        ).first()
        if membership is None:
            return None, "organization_mismatch"
    return license_key, None


def bind_machine_id(db, license_key: LicenseKey, machine_id: str, *, commit: bool = True) -> None:
    """Pins machine_id to the license on first use only -- parity with
    license_server.py's behavior, not an enforced device-count limit
    (LicenseKey.max_devices stays unused/reserved). Never overwrites an
    already-bound machine_id.
    """
    if license_key.machine_id is None:
        license_key.machine_id = machine_id
        db.add(license_key)
        if commit:
            db.commit()


def mark_used(db, license_key: LicenseKey, user: User, *, commit: bool = True) -> bool:
    """Consumes an activation only on first bind; every later call from the
    same now-bound owner is a sign-in, not a new use (see the matching
    guard in validate_and_consume) -- last_used_at still advances every time
    so /license/status keeps reflecting the most recent sign-in.
    """
    first_activation = license_key.last_used_at is None
    if license_key.user_id is None:
        license_key.usage_count += 1
        license_key.user_id = user.id
    license_key.last_used_at = utc_now()
    db.add(license_key)
    if commit:
        db.commit()
    return first_activation


def get_status_for_user(db, user_id: int) -> LicenseKey | None:
    return (
        db.query(LicenseKey)
        .filter(LicenseKey.user_id == user_id)
        .order_by(LicenseKey.created_at.desc())
        .first()
    )


def revoke(db, key: str, reason: str | None = None) -> bool:
    license_key = lookup_license(db, key, lock=True)
    if not license_key:
        return False
        license_key.revoked_at = utc_now()
    license_key.revoked_reason = reason
    db.commit()
    return True
