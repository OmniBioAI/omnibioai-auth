"""
OmniBioAI app.api.routes_apikeys.

Purpose:
    Defines HTTP route handlers for app.api.routes_apikeys, including create_api_key, list_api_keys, rename_api_key and revoke_api_key.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import hmac
import json

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.api import routes_auth
from app.core.config import settings
from app.db.models import ApiKey, OrganizationMembership
from app.db.session import get_db
from app.rbac import get_current_user, require_org_permission_or_platform_admin
from app.schemas.apikeys import ApiKeyCreate, ApiKeyCreated, ApiKeyExchangeIn, ApiKeyExchangeOut, ApiKeyOut, ApiKeyRename
from app.services import apikey_service, billing_client, org_service

router = APIRouter(prefix="/orgs/{org_id}/api-keys", tags=["api-keys"])
exchange_router = APIRouter(prefix="/auth/api-keys", tags=["api-keys"])
me_router = APIRouter(prefix="/me/api-keys", tags=["api-keys"])

MANAGE_API_KEYS = "manage_api_keys"


def _key_out(key: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes or [],
        status=key.status,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        test=apikey_service.is_test_key(key),
    )


@router.post("", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    org_id: int,
    body: ApiKeyCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_API_KEYS)),
):
    caller_permissions = org_service.permissions_for_membership(membership)
    try:
        api_key, full_key = apikey_service.create_api_key(
            db, org_id, membership.user_id, body.name, body.scopes, caller_permissions,
            expires_at=body.expires_at, test=body.test,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return ApiKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes or [],
        expires_at=api_key.expires_at,
        test=body.test,
        key=full_key,
    )


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_API_KEYS)),
):
    return [_key_out(k) for k in apikey_service.list_api_keys(db, org_id)]


@router.patch("/{key_id}", response_model=ApiKeyOut)
def rename_api_key(
    org_id: int,
    key_id: int,
    body: ApiKeyRename,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_API_KEYS)),
):
    key = apikey_service.get_api_key(db, org_id, key_id)
    if not key:
        raise HTTPException(404, "API key not found")
    try:
        apikey_service.rename_api_key(db, key, body.name, actor_user_id=membership.user_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _key_out(key)


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(
    org_id: int,
    key_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_API_KEYS)),
):
    key = apikey_service.get_api_key(db, org_id, key_id)
    if not key:
        raise HTTPException(404, "API key not found")
    apikey_service.revoke_api_key(db, key, actor_user_id=membership.user_id)
    _publish_key_revoked(key)


def _publish_key_revoked(key: ApiKey) -> None:
    # Same policy:invalidate channel logout uses: the gateway drops its
    # cached exchange for this key at once instead of waiting for the TTL.
    # Only the stored hash is published, never key material.
    try:
        routes_auth._pub.publish("policy:invalidate", json.dumps({"api_key_hash": key.key_hash}))
    except Exception:
        pass


@exchange_router.post("/exchange", response_model=ApiKeyExchangeOut)
def exchange_api_key(
    body: ApiKeyExchangeIn,
    db: Session = Depends(get_db),
    x_api_key_exchange_secret: str = Header(default=""),
):
    """Gateway-only: trade an omni_sk_live_/omni_sk_test_ (or a pre-M13
    bare omni_sk_) key for a short-lived access token.

    Callable only with the shared API_KEY_EXCHANGE_SECRET, so the minted
    token can't be obtained by a key holder directly and used to reach
    services around the gateway's metering. Every failure is the same 401,
    so the response never says whether a key exists, is revoked, or
    belongs to a removed user.
    """
    expected = settings.API_KEY_EXCHANGE_SECRET
    if not expected:
        raise HTTPException(503, "API key exchange is not configured")
    if not hmac.compare_digest(x_api_key_exchange_secret.encode(), expected.encode()):
        raise HTTPException(403, "Forbidden")
    result = apikey_service.exchange_api_key(db, body.api_key)
    if result is None:
        raise HTTPException(401, "Invalid API key")
    return ApiKeyExchangeOut(**result)


# ---------------------------------------------------------------------------
# Self-service keys (/me/api-keys): any signed-in member manages their *own*
# keys in the organization their session is in (the token's org_id), with
# scopes limited to permissions they hold there -- the Studio Developer page.
# Org admins keep the org-wide /orgs/{org_id}/api-keys routes above.
# ---------------------------------------------------------------------------

MAX_ACTIVE_KEYS_PER_USER = 10

# M9 (API-key lifecycle, design doc's "Scopes" section): the public,
# developer-facing scope vocabulary self-service keys are issued and
# displayed in -- distinct from the internal dot-format IAM permission
# names (app/core/permission_names.py's registry) that org roles are
# actually granted and that create_api_key/exchange_api_key check
# against. Translating at this HTTP boundary only, rather than renaming
# dataset.read/usage.read themselves, keeps both of those exactly as they
# are everywhere else they're used -- role grants, the org-admin
# /orgs/{org_id}/api-keys router below, and every downstream consumer of
# an exchanged token's `permissions` claim (the gateway and policy engine
# still see "dataset.read"/"usage.read", unchanged).
PUBLIC_SCOPE_TO_PERMISSION = {
    "literature:read": "dataset.read",
    "usage:read": "usage.read",
}
PERMISSION_TO_PUBLIC_SCOPE = {v: k for k, v in PUBLIC_SCOPE_TO_PERMISSION.items()}

DEFAULT_SELF_SERVICE_SCOPES = ["literature:read"]


def _to_public_scopes(internal_scopes: list[str]) -> list[str]:
    return [PERMISSION_TO_PUBLIC_SCOPE.get(s, s) for s in internal_scopes]


def _self_service_membership(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OrganizationMembership:
    # An API key's own token must never mint or manage keys.
    if user.get("auth_method") == "api_key":
        raise HTTPException(403, "API keys cannot manage API keys")
    org_id = user.get("org_id")
    if org_id is None:
        raise HTTPException(400, "Your session is not in an organization")
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == int(user["sub"]),
        )
        .first()
    )
    if membership is None or (membership.status or "active") != "active":
        raise HTTPException(403, "Not an active member of this organization")
    return membership


def _own_keys(db: Session, membership: OrganizationMembership):
    return (
        db.query(ApiKey)
        .filter(
            ApiKey.organization_id == membership.organization_id,
            ApiKey.created_by_user_id == membership.user_id,
        )
        .order_by(ApiKey.id.desc())
    )


def _me_key_out(key: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=_to_public_scopes(key.scopes or []),
        status=key.status,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        test=apikey_service.is_test_key(key),
    )


@me_router.get("", response_model=list[ApiKeyOut])
def list_my_api_keys(
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(_self_service_membership),
):
    return [_me_key_out(k) for k in _own_keys(db, membership).all()]


@me_router.post("", response_model=ApiKeyCreated, status_code=201)
def create_my_api_key(
    body: ApiKeyCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(_self_service_membership),
):
    active = _own_keys(db, membership).filter(ApiKey.status == "active").count()
    if active >= MAX_ACTIVE_KEYS_PER_USER:
        raise HTTPException(409, f"At most {MAX_ACTIVE_KEYS_PER_USER} active keys; revoke one first")
    # M17 (design audit gap #9): auto-enrollment (billing-service's own
    # get_subscription_summary) means a brand-new organization's first
    # call here still succeeds -- this only actually blocks an
    # organization whose subscription has gone to "suspended" (mid
    # payment-failure grace period) or "cancelled". Fails open on a
    # billing-service outage (see billing_client's own docstring).
    if not billing_client.organization_has_active_plan(membership.organization_id):
        raise HTTPException(
            402, "Your organization has no active billing plan. "
                 "Resolve any payment issue, or reactivate a plan, before creating new API keys.",
        )
    public_scopes = body.scopes or DEFAULT_SELF_SERVICE_SCOPES
    unknown_scopes = set(public_scopes) - set(PUBLIC_SCOPE_TO_PERMISSION)
    if unknown_scopes:
        raise HTTPException(400, f"Unknown scope(s): {sorted(unknown_scopes)}")
    internal_scopes = [PUBLIC_SCOPE_TO_PERMISSION[s] for s in public_scopes]
    try:
        api_key, full_key = apikey_service.create_api_key(
            db, membership.organization_id, membership.user_id, body.name, internal_scopes,
            org_service.permissions_for_membership(membership),
            expires_at=body.expires_at, test=body.test,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return ApiKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=_to_public_scopes(api_key.scopes or []),
        expires_at=api_key.expires_at,
        test=body.test,
        key=full_key,
    )


@me_router.patch("/{key_id}", response_model=ApiKeyOut)
def rename_my_api_key(
    key_id: int,
    body: ApiKeyRename,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(_self_service_membership),
):
    key = _own_keys(db, membership).filter(ApiKey.id == key_id).first()
    if not key:
        raise HTTPException(404, "API key not found")
    try:
        apikey_service.rename_api_key(db, key, body.name, actor_user_id=membership.user_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _me_key_out(key)


@me_router.delete("/{key_id}", status_code=204)
def revoke_my_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(_self_service_membership),
):
    key = _own_keys(db, membership).filter(ApiKey.id == key_id).first()
    if not key:
        raise HTTPException(404, "API key not found")
    if key.status != "revoked":
        apikey_service.revoke_api_key(db, key, actor_user_id=membership.user_id)
        _publish_key_revoked(key)
