import secrets
import string
from datetime import datetime, timedelta

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


def create_license(
    db,
    email: str,
    plan: str = "beta",
    platform: str = "both",
    expires_days: int | None = None,
    max_uses: int = 1,
) -> LicenseKey:
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
    license_key = db.query(LicenseKey).filter(LicenseKey.key == key).first()
    if not license_key:
        return None, "invalid_key"

    if license_key.revoked_at is not None:
        return None, "revoked"

    if license_key.expires_at is not None and license_key.expires_at < datetime.utcnow():
        return None, "expired"

    if license_key.usage_count >= license_key.max_uses:
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
    license_key.usage_count += 1
    license_key.last_used_at = datetime.utcnow()
    if license_key.user_id is None:
        license_key.user_id = user.id
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
