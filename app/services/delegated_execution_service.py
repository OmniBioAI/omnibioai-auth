"""Typed issuance and live validation for TES-to-ToolServer delegation."""
from datetime import datetime, timedelta
import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_delegated_execution_token, decode_token, decode_token_for_audience
from app.core.permission_names import is_known_permission
from app.core.token_revocation import assert_token_usable
from app.db.models import DelegatedExecutionGrant, OAuthClient, Organization, OrganizationMembership, User
from app.services import org_service, role_service

TOOLSERVER_AUDIENCE = "omnibioai-toolserver"
DELEGATION_SCOPE = "toolserver.delegate"
ACCEPTED_PERMISSIONS = {"workflow.execute", "runs.read"}


def _active_service(db: Session, service_token: str) -> tuple[dict, OAuthClient]:
    try:
        payload = decode_token(service_token)
    except Exception as exc:
        raise HTTPException(401, "Invalid service token") from exc
    if payload.get("auth_method") != "client_credentials":
        raise HTTPException(403, "Service token required")
    client = db.query(OAuthClient).filter(OAuthClient.client_id == payload.get("client_id")).first()
    if client is None or client.status != "active" or (client.expires_at and client.expires_at < datetime.utcnow()):
        raise HTTPException(403, "Service identity is inactive")
    if str(payload.get("org_id")) != str(client.organization_id):
        raise HTTPException(403, "Service identity mismatch")
    token_scopes, current_scopes = set(payload.get("scopes") or []), set(client.scopes or [])
    if DELEGATION_SCOPE not in token_scopes or DELEGATION_SCOPE not in current_scopes:
        raise HTTPException(403, "Service delegation not authorized")
    return payload, client


def _user_membership(db: Session, token: str, organization_id: int) -> tuple[User, OrganizationMembership]:
    try:
        payload = decode_token(token)
        if payload.get("type") != "access" or payload.get("auth_method") == "client_credentials":
            raise ValueError("not a user access token")
        assert_token_usable(payload, db)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise HTTPException(403, "Invalid initiating identity") from exc
    user = db.query(User).filter(User.id == user_id, User.status == "active").first()
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.status == "active",
    ).first()
    if user is None or org is None or membership is None:
        raise HTTPException(403, "Delegation context unavailable")
    return user, membership


def _user_permissions(user: User, membership: OrganizationMembership) -> set[str]:
    return role_service.permissions_for_roles(user.roles) | org_service.permissions_for_membership(membership)


def issue(db: Session, *, service_token: str, initiating_token: str, organization_id: int,
          permissions: list[str], audience: str) -> tuple[str, DelegatedExecutionGrant]:
    service_payload, service = _active_service(db, service_token)
    if audience != TOOLSERVER_AUDIENCE:
        raise HTTPException(400, "Unsupported delegation audience")
    requested = set(permissions)
    if not requested or not requested <= ACCEPTED_PERMISSIONS or any(not is_known_permission(p) for p in requested):
        raise HTTPException(400, "Unsupported delegated permission")
    user, membership = _user_membership(db, initiating_token, organization_id)
    service_permissions = set(service_payload.get("scopes") or []) & set(service.scopes or [])
    if not requested <= _user_permissions(user, membership) or not requested <= service_permissions:
        raise HTTPException(403, "Delegated permission denied")
    delegation_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=settings.DELEGATED_EXECUTION_TOKEN_EXPIRE_MINUTES)
    grant = DelegatedExecutionGrant(
        delegation_id=delegation_id, client_id=service.client_id, user_id=user.id,
        organization_id=organization_id, permissions=sorted(requested), audience=audience, expires_at=expires_at,
    )
    db.add(grant)
    db.commit()
    return create_delegated_execution_token(
        client_id=service.client_id, user_id=user.id, organization_id=organization_id,
        permissions=sorted(requested), delegation_id=delegation_id,
    ), grant


def introspect(db: Session, token: str) -> dict | None:
    try:
        payload = decode_token_for_audience(token, TOOLSERVER_AUDIENCE)
        if payload.get("type") != "delegated_execution":
            return None
        delegation_id = str(payload["delegation_id"])
        if payload.get("jti") != delegation_id:
            return None
        assert_token_usable(payload, db)
        grant = db.query(DelegatedExecutionGrant).filter(
            DelegatedExecutionGrant.delegation_id == delegation_id,
            DelegatedExecutionGrant.revoked_at.is_(None),
        ).first()
        if grant is None or grant.expires_at < datetime.utcnow():
            return None
        if (grant.client_id != payload.get("client_id") or str(grant.user_id) != str(payload.get("sub")) or
                str(grant.organization_id) != str(payload.get("org_id")) or grant.audience != payload.get("aud") or
                sorted(grant.permissions or []) != sorted(payload.get("permissions") or [])):
            return None
        client = db.query(OAuthClient).filter(OAuthClient.client_id == grant.client_id).first()
        user = db.query(User).filter(User.id == grant.user_id, User.status == "active").first()
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.user_id == grant.user_id,
            OrganizationMembership.organization_id == grant.organization_id,
            OrganizationMembership.status == "active",
        ).first()
        if client is None or client.status != "active" or user is None or membership is None:
            return None
        # Same nullable expiry and UTC comparison as verify_client_credentials.
        if client.expires_at and client.expires_at < datetime.utcnow():
            return None
        if DELEGATION_SCOPE not in set(client.scopes or []):
            return None
        if not set(grant.permissions or []) <= set(client.scopes or []):
            return None
        if not set(grant.permissions or []) <= _user_permissions(user, membership):
            return None
        return {"client_id": grant.client_id, "user_id": str(grant.user_id),
                "organization_id": str(grant.organization_id), "permissions": list(grant.permissions or []),
                "delegation_id": delegation_id}
    except Exception:
        return None
