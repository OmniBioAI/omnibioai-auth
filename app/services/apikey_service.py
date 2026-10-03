import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import _sign
from app.db.models import ApiKey, OrganizationMembership, User
from app.services import audit_service
from app.services.audit_service import AuditEventType

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
    db.flush()
    db.refresh(api_key)
    # PR11.4b: never the plaintext key or its hash in audit metadata --
    # only the name/scopes an admin reviewing the trail actually needs.
    audit_service.log_event(
        db, AuditEventType.API_KEY_CREATED, actor_user_id=creator_user_id,
        organization_id=organization_id, resource_type="api_key", resource_id=api_key.id,
        after_state={"name": api_key.name, "scopes": api_key.scopes, "status": api_key.status},
        metadata={"api_key_name": api_key.name, "scopes": api_key.scopes},
        commit=False,
    )
    db.commit()
    return api_key, full_key


def list_api_keys(db: Session, organization_id: int) -> list[ApiKey]:
    return db.query(ApiKey).filter(ApiKey.organization_id == organization_id).all()


def get_api_key(db: Session, organization_id: int, key_id: int) -> ApiKey | None:
    return (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.organization_id == organization_id)
        .first()
    )


def revoke_api_key(
    db: Session, api_key: ApiKey, reason: str | None = None, actor_user_id: int | None = None,
) -> ApiKey:
    api_key.status = "revoked"
    api_key.revoked_at = datetime.utcnow()
    api_key.revoked_reason = reason
    db.flush()
    db.refresh(api_key)
    # PR11.4b. `actor_user_id` is a new, optional kwarg (see
    # docs/pr11-identity-audit-discovery.md §4b) -- backward compatible
    # for any caller that doesn't pass it, though routes_apikeys.py
    # always does.
    audit_service.log_event(
        db, AuditEventType.API_KEY_REVOKED, actor_user_id=actor_user_id,
        organization_id=api_key.organization_id, resource_type="api_key", resource_id=api_key.id,
        before_state={"status": "active"}, after_state={"status": "revoked"},
        metadata={"api_key_name": api_key.name, "scopes": api_key.scopes, "reason": reason},
        commit=False,
    )
    db.commit()
    return api_key


def verify_api_key(db: Session, full_key: str) -> ApiKey | None:
    """Look up an active, unexpired key by the hash of its full value.
    Used by exchange_api_key() below (POST /auth/api-keys/exchange)."""
    key_hash = _hash_key(full_key)
    api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
    if not api_key or api_key.status != "active":
        return None
    if api_key.expires_at and api_key.expires_at < datetime.utcnow():
        return None
    return api_key


# last_used_at is written at most once per this many seconds per key, so a
# busy key does not turn every API request into a database write.
_LAST_USED_WRITE_INTERVAL = timedelta(seconds=60)


def hash_api_key(full_key: str) -> str:
    """Public form of _hash_key for callers that need the stored hash (e.g.
    the revocation invalidation message), never the key itself."""
    return _hash_key(full_key)


def exchange_api_key(db: Session, full_key: str) -> dict | None:
    """Trade a valid omni_sk_ key for a short-lived access token.

    Returns None (caller answers 401) unless the key is active and
    unexpired, its creator is still an active user, and the creator is
    still an active member of the key's organization. The token's
    permissions are the key's scopes intersected with the creator's
    *current* membership permissions, so a key loses whatever its issuer
    loses -- it never outlives a demotion or removal from the org.

    The token carries auth_method="api_key" and api_key_id so downstream
    services and audit can tell API traffic from interactive sessions. No
    global roles are included: an API key acts only inside its own org.
    """
    from app.services import org_service  # local: org_service imports this module's siblings

    if not full_key or not full_key.startswith(_PREFIX):
        return None
    api_key = verify_api_key(db, full_key)
    if api_key is None:
        return None

    user = db.query(User).filter(User.id == api_key.created_by_user_id).first()
    if user is None or (user.status or "active") != "active":
        return None
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == api_key.organization_id,
            OrganizationMembership.user_id == user.id,
        )
        .first()
    )
    if membership is None or (membership.status or "active") != "active":
        return None

    permissions = sorted(set(api_key.scopes or []) & org_service.permissions_for_membership(membership))

    now = datetime.utcnow()
    expires_in = settings.API_KEY_TOKEN_EXPIRE_MINUTES * 60
    token = _sign({
        "sub": str(user.id),
        "email": user.email,
        "roles": [],
        "permissions": permissions,
        "org_id": api_key.organization_id,
        "org_role": [],
        "team_id": None,
        "team_role": None,
        "auth_method": "api_key",
        "api_key_id": api_key.id,
        "idp_org_id": None,
        "token_version": 2,
        "mfa_verified": False,
        "exp": now + timedelta(seconds=expires_in),
        "type": "access",
        "jti": str(uuid.uuid4()),
    })

    if api_key.last_used_at is None or now - api_key.last_used_at >= _LAST_USED_WRITE_INTERVAL:
        api_key.last_used_at = now
        db.commit()

    return {
        "access_token": token,
        "expires_in": expires_in,
        "api_key_id": api_key.id,
        "organization_id": api_key.organization_id,
        "user_id": user.id,
        "permissions": permissions,
    }
