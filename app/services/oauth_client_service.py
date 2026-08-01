import hashlib
import secrets
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import OAuthClient

_CLIENT_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_CLIENT_ID_LENGTH = 24
_CLIENT_ID_PREFIX = "omni_client_"

_SECRET_ALPHABET = _CLIENT_ID_ALPHABET
_SECRET_LENGTH = 40


def _generate_client_id() -> str:
    return _CLIENT_ID_PREFIX + "".join(
        secrets.choice(_CLIENT_ID_ALPHABET) for _ in range(_CLIENT_ID_LENGTH)
    )


def _generate_client_secret() -> str:
    return "".join(secrets.choice(_SECRET_ALPHABET) for _ in range(_SECRET_LENGTH))


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_oauth_client(
    db: Session,
    organization_id: int,
    creator_user_id: int,
    name: str,
    scopes: list[str],
    caller_permissions: set[str],
) -> tuple[OAuthClient, str]:
    """Returns (OAuthClient row, plaintext client_secret). The plaintext is
    never persisted -- only its sha256 hash is stored -- so this is the
    only moment the caller can see it. Mirrors apikey_service.create_api_key.

    `caller_permissions` gates what scopes can be granted: a client's
    scopes must never exceed what the issuing user themselves holds in
    this org, or OAuth clients become a privilege-escalation path, same
    reasoning as API keys.
    """
    invalid_scopes = set(scopes) - caller_permissions
    if invalid_scopes:
        raise ValueError(f"Cannot grant scopes you don't hold: {sorted(invalid_scopes)}")

    client_id = _generate_client_id()
    while db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first():
        client_id = _generate_client_id()

    client_secret = _generate_client_secret()
    oauth_client = OAuthClient(
        organization_id=organization_id,
        created_by_user_id=creator_user_id,
        client_id=client_id,
        client_secret_hash=_hash_secret(client_secret),
        name=name,
        scopes=scopes,
        status="active",
        created_at=datetime.utcnow(),
    )
    db.add(oauth_client)
    db.commit()
    db.refresh(oauth_client)
    return oauth_client, client_secret


def list_oauth_clients(db: Session, organization_id: int) -> list[OAuthClient]:
    return db.query(OAuthClient).filter(OAuthClient.organization_id == organization_id).all()


def get_oauth_client(db: Session, organization_id: int, client_id: int) -> OAuthClient | None:
    return (
        db.query(OAuthClient)
        .filter(OAuthClient.id == client_id, OAuthClient.organization_id == organization_id)
        .first()
    )


def revoke_oauth_client(db: Session, oauth_client: OAuthClient, reason: str | None = None) -> OAuthClient:
    oauth_client.status = "revoked"
    oauth_client.revoked_at = datetime.utcnow()
    oauth_client.revoked_reason = reason
    db.commit()
    db.refresh(oauth_client)
    return oauth_client


def verify_client_credentials(db: Session, client_id: str, client_secret: str) -> OAuthClient | None:
    """Looks up by the public client_id (not a hash of it -- client_id is
    not a secret, only client_secret is), then confirms the presented
    secret's hash matches. Returns None on any mismatch, revoked status,
    or expiry -- callers must not distinguish these cases in the response
    (RFC 6749 SS5.2: invalid_client covers all of them alike)."""
    oauth_client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if not oauth_client or oauth_client.status != "active":
        return None
    if oauth_client.expires_at and oauth_client.expires_at < datetime.utcnow():
        return None
    if oauth_client.client_secret_hash != _hash_secret(client_secret):
        return None
    return oauth_client


def mark_used(db: Session, oauth_client: OAuthClient) -> None:
    oauth_client.last_used_at = datetime.utcnow()
    db.add(oauth_client)
    db.commit()
