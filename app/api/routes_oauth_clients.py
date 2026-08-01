from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OAuthClient, OrganizationMembership
from app.db.session import get_db
from app.rbac import require_org_permission
from app.schemas.oauth_client import OAuthClientCreate, OAuthClientCreated, OAuthClientOut
from app.services import oauth_client_service, org_service

router = APIRouter(prefix="/orgs/{org_id}/oauth-clients", tags=["oauth-clients"])

MANAGE_OAUTH_CLIENTS = "manage_oauth_clients"


def _client_out(client: OAuthClient) -> OAuthClientOut:
    return OAuthClientOut(
        id=client.id,
        name=client.name,
        client_id=client.client_id,
        scopes=client.scopes or [],
        status=client.status,
        created_at=client.created_at,
        expires_at=client.expires_at,
        last_used_at=client.last_used_at,
    )


@router.post("", response_model=OAuthClientCreated, status_code=201)
def create_oauth_client(
    org_id: int,
    body: OAuthClientCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_OAUTH_CLIENTS)),
):
    caller_permissions = org_service.permissions_for_membership(membership)
    try:
        oauth_client, client_secret = oauth_client_service.create_oauth_client(
            db, org_id, membership.user_id, body.name, body.scopes, caller_permissions
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return OAuthClientCreated(
        id=oauth_client.id,
        name=oauth_client.name,
        client_id=oauth_client.client_id,
        scopes=oauth_client.scopes or [],
        client_secret=client_secret,
    )


@router.get("", response_model=list[OAuthClientOut])
def list_oauth_clients(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_OAUTH_CLIENTS)),
):
    return [_client_out(c) for c in oauth_client_service.list_oauth_clients(db, org_id)]


@router.delete("/{client_id}", status_code=204)
def revoke_oauth_client(
    org_id: int,
    client_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_OAUTH_CLIENTS)),
):
    client = oauth_client_service.get_oauth_client(db, org_id, client_id)
    if not client:
        raise HTTPException(404, "OAuth client not found")
    oauth_client_service.revoke_oauth_client(db, client)
