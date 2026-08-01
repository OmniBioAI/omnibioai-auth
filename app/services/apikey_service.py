import hashlib
import secrets
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import ApiKey

_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SECRET_LENGTH = 40
_PREFIX = "omni_sk_"


def _generate_key() -> str:
    return _PREFIX + "".join(secrets.choice(_ALPHABET) for _ in range(_SECRET_LENGTH))


def _hash_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode()).hexdigest()


def create_api_key(
    db: Session,
    organization_id: int,
    creator_user_id: int,
    name: str,
    scopes: list[str],
    caller_permissions: set[str],
) -> tuple[ApiKey, str]:
    """Returns (ApiKey row, full plaintext key). The plaintext is never
    persisted -- only its sha256 hash is stored -- so this is the only
    moment the caller can see it.

    `caller_permissions` gates what scopes can be granted: a key's scopes
    must never exceed what the issuing user themselves holds in this org,
    or API keys become a privilege-escalation path (see
    ~/phase1_design.md security considerations).
    """
    invalid_scopes = set(scopes) - caller_permissions
    if invalid_scopes:
        raise ValueError(f"Cannot grant scopes you don't hold: {sorted(invalid_scopes)}")

    full_key = _generate_key()
    api_key = ApiKey(
        organization_id=organization_id,
        created_by_user_id=creator_user_id,
        name=name,
        key_prefix=full_key[: len(_PREFIX) + 4],
        key_hash=_hash_key(full_key),
        scopes=scopes,
        status="active",
        created_at=datetime.utcnow(),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return api_key, full_key


def list_api_keys(db: Session, organization_id: int) -> list[ApiKey]:
    return db.query(ApiKey).filter(ApiKey.organization_id == organization_id).all()


def get_api_key(db: Session, organization_id: int, key_id: int) -> ApiKey | None:
    return (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.organization_id == organization_id)
        .first()
    )


def revoke_api_key(db: Session, api_key: ApiKey, reason: str | None = None) -> ApiKey:
    api_key.status = "revoked"
    api_key.revoked_at = datetime.utcnow()
    api_key.revoked_reason = reason
    db.commit()
    db.refresh(api_key)
    return api_key


def verify_api_key(db: Session, full_key: str) -> ApiKey | None:
    """Not yet wired into a route or consumed by any other service --
    ready for Phase 1 PR3, when the gateway/iam-client start trusting API
    keys the same way they trust JWTs today. Included now so the
    hashing/lookup contract is established and tested alongside key
    creation, rather than retrofitted later."""
    key_hash = _hash_key(full_key)
    api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
    if not api_key or api_key.status != "active":
        return None
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        return None
    return api_key
