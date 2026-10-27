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
from datetime import datetime, timedelta

from sqlalchemy import func, or_

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


def utc_now() -> datetime:
    """Return UTC as a naive datetime compatible with existing DB columns."""
    return datetime.utcnow()


def normalize_key(key: str) -> str:
    return key.strip().upper()


def digest_key(key: str) -> str:
    if not settings.LICENSE_KEY_PEPPER:
        raise RuntimeError("LICENSE_KEY_PEPPER is required for new license issuance")
    return hmac.new(
        settings.LICENSE_KEY_PEPPER.encode("utf-8"),
        normalize_key(key).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def lookup_license(db, key: str, *, lock: bool = False) -> LicenseKey | None:
    """Resolve digest-only new keys and still-valid plaintext legacy rows."""
    normalized = normalize_key(key)
    query = db.query(LicenseKey)
    if lock:
        query = query.with_for_update()
    if settings.LICENSE_KEY_PEPPER:
        found = query.filter(LicenseKey.key_digest == digest_key(normalized)).first()
        if found:
            return found
    return query.filter(LicenseKey.key == normalized, LicenseKey.key_digest.is_(None)).first()


def masked_key(license_key: LicenseKey | str) -> str:
    if isinstance(license_key, str):
        prefix = license_key[:9]
    else:
        prefix = license_key.key_prefix or ((license_key.key or "")[:9]) or "OMNI"
    return f"{prefix}-••••-••••-••••"


def create_license(
    db,
    email: str,
    plan: str = "beta",
    platform: str = "both",
    expires_days: int | None = None,
    max_uses: int = 1,
    *,
    commit: bool = True,
) -> LicenseKey:
    """``commit=False`` flushes instead, so a caller can commit the license
    and its audit row together."""
    key = generate_key()
    # Astronomically unlikely, but a live service shouldn't silently accept
    # a collision — regenerate rather than fail the caller's request.
    while db.query(LicenseKey).filter(LicenseKey.key == key).first():
        key = generate_key()

    license_key = LicenseKey(
        key=key,
        email=email,
        plan=plan,
        platform=platform,
        max_uses=max_uses,
        expires_at=(
            datetime.utcnow() + timedelta(days=expires_days)
            if expires_days is not None
            else None
        ),
    )
    db.add(license_key)
    if not commit:
        db.flush()
        return license_key
    db.commit()
    db.refresh(license_key)
    return license_key


def create_manual_license(
    db,
    *,
    email: str,
    user_id: int,
    organization_id: int,
    plan: str = "beta",
    platform: str = "both",
    expires_days: int,
    max_uses: int = 1,
    recipient_name: str | None = None,
    commit: bool = True,
) -> LicenseKey:
    """Create a new digest-only key; the plaintext is returned only once."""
    key = generate_key()
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
        expires_at=utc_now() + timedelta(days=expires_days),
    )
    db.add(license_key)
    db.flush()
    license_key._one_time_key = key
    if commit:
        db.commit()
        db.refresh(license_key)
    return license_key


def masked_key(key: str) -> str:
    """OMNI-ABCD-••••-••••-•••• -- enough to recognize a key in an audit
    trail, never enough to use it."""
    return key[:9] + "-••••-••••-••••"


def is_email_approved(db, email: str) -> bool:
    """True when a live license (not revoked, not expired) is addressed to
    this email, whatever its plan or activation state. Gates only the
    creation of a NEW account through SSO; existing accounts never need it.
    """
    return (
        db.query(LicenseKey.id)
        .filter(
            func.lower(LicenseKey.email) == email.lower(),
            LicenseKey.revoked_at.is_(None),
            or_(LicenseKey.expires_at.is_(None), LicenseKey.expires_at > datetime.utcnow()),
        )
        .first()
        is not None
    )


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


def bind_machine_id(db, license_key: LicenseKey, machine_id: str) -> None:
    """Pins machine_id to the license on first use only -- parity with
    license_server.py's behavior, not an enforced device-count limit
    (LicenseKey.max_devices stays unused/reserved). Never overwrites an
    already-bound machine_id.
    """
    if license_key.machine_id is None:
        license_key.machine_id = machine_id
        db.add(license_key)
        db.commit()


def mark_used(db, license_key: LicenseKey, user: User) -> None:
    """Consumes an activation only on first bind; every later call from the
    same now-bound owner is a sign-in, not a new use (see the matching
    guard in validate_and_consume) -- last_used_at still advances every time
    so /license/status keeps reflecting the most recent sign-in.
    """
    if license_key.user_id is None:
        license_key.usage_count += 1
        license_key.user_id = user.id
    license_key.last_used_at = datetime.utcnow()
    db.add(license_key)
    db.commit()


def get_status_for_user(db, user_id: int) -> LicenseKey | None:
    return (
        db.query(LicenseKey)
        .filter(LicenseKey.user_id == user_id)
        .order_by(LicenseKey.created_at.desc())
        .first()
    )


def revoke(db, key: str, reason: str | None = None) -> bool:
    license_key = db.query(LicenseKey).filter(LicenseKey.key == key).first()
    if not license_key:
        return False
    license_key.revoked_at = datetime.utcnow()
    license_key.revoked_reason = reason
    db.commit()
    return True
