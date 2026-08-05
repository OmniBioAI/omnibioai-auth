from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import ApiKey, OrganizationMembership
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin
from app.schemas.apikeys import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.services import apikey_service, org_service

router = APIRouter(prefix="/orgs/{org_id}/api-keys", tags=["api-keys"])

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
            db, org_id, membership.user_id, body.name, body.scopes, caller_permissions
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return ApiKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes or [],
        key=full_key,
    )


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_API_KEYS)),
):
    return [_key_out(k) for k in apikey_service.list_api_keys(db, org_id)]


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
