import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import _sign
from app.db.models import ApiKey, OrganizationMembership, User
from app.services import audit_service
from app.services.audit_service import AuditEventType

_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SECRET_LENGTH = 40
# M13 (design audit gap #9): omni_sk_live_/omni_sk_test_ replace the single
# omni_sk_ prefix every key issued before this milestone still uses. Both
# new prefixes start with the old bare one, so is_test_key()/exchange_api_key
# below stay the only two places that need to know the difference --
# every pre-M13 key is unambiguously "live" (it predates test mode
# existing at all), and nothing else anywhere needs to distinguish the
# three shapes. _PREFIX stays the "is this an API key at all" check (also
# used, unchanged, by omnibioai-api-gateway's own is_api_key()).
_PREFIX = "omni_sk_"
_LIVE_PREFIX = "omni_sk_live_"
_TEST_PREFIX = "omni_sk_test_"


def _generate_key(test: bool = False) -> str:
    prefix = _TEST_PREFIX if test else _LIVE_PREFIX
    return prefix + "".join(secrets.choice(_ALPHABET) for _ in range(_SECRET_LENGTH))


def is_test_key(api_key: ApiKey) -> bool:
    """Whether `api_key` is a test-mode key (omni_sk_test_) -- derived from
    the already-stored, non-secret key_prefix rather than a separate DB
    column, since that prefix already encodes the answer. A pre-M13 key
    (bare omni_sk_ prefix) is always False: it predates test mode, so it
    is unambiguously live, the same posture a pre-M9 key's scopes get
    read with (see routes_apikeys.py's _to_public_scopes fallback)."""
    return bool(api_key.key_prefix) and api_key.key_prefix.startswith(_TEST_PREFIX)


def _hash_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode()).hexdigest()


def _normalize_expiry(expires_at: datetime | None) -> datetime | None:
    """Every other timestamp on this model (created_at, last_used_at,
    revoked_at) is a naive UTC datetime.utcnow(), and verify_api_key's own
    expiry check compares against one -- so a caller-supplied, possibly
    tz-aware expires_at is converted to the same naive-UTC shape here,
    once, rather than every comparison site needing to handle both."""
    if expires_at is None:
        return None
    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
    return expires_at


def create_api_key(
    db: Session,
    organization_id: int,
    creator_user_id: int,
    name: str,
    scopes: list[str],
    caller_permissions: set[str],
    expires_at: datetime | None = None,
    test: bool = False,
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

    expires_at = _normalize_expiry(expires_at)
    if expires_at is not None and expires_at <= datetime.utcnow():
        raise ValueError("expires_at must be in the future")

    full_key = _generate_key(test=test)
    prefix_len = len(_TEST_PREFIX if test else _LIVE_PREFIX)
    api_key = ApiKey(
        organization_id=organization_id,
        created_by_user_id=creator_user_id,
        name=name,
        key_prefix=full_key[: prefix_len + 4],
        key_hash=_hash_key(full_key),
        scopes=scopes,
        status="active",
        created_at=datetime.utcnow(),
        expires_at=expires_at,
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


def rename_api_key(
    db: Session, api_key: ApiKey, new_name: str, actor_user_id: int | None = None,
) -> ApiKey:
    """Change a key's display name only -- scopes, status, and the key
    material itself are untouched, so this never needs the
    caller_permissions re-check create_api_key does."""
    if not new_name or not new_name.strip():
        raise ValueError("name must not be empty")
    old_name = api_key.name
    api_key.name = new_name
    db.flush()
    db.refresh(api_key)
    audit_service.log_event(
        db, AuditEventType.API_KEY_RENAMED, actor_user_id=actor_user_id,
        organization_id=api_key.organization_id, resource_type="api_key", resource_id=api_key.id,
        before_state={"name": old_name}, after_state={"name": api_key.name},
        metadata={"old_name": old_name, "new_name": api_key.name},
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
        # M13: the gateway reads this to serve a canned, unbilled response
        # instead of forwarding to RAG/consuming real quota -- see
        # omnibioai-api-gateway's app/routes/v1.py.
        "test_mode": is_test_key(api_key),
    }
