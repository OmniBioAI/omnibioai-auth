"""Artifact-audience delegation using the existing OAuth/grant architecture."""
from datetime import datetime, timedelta
import re
import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_artifact_delegation_token, decode_token_for_audience
from app.core.token_revocation import assert_token_usable
from app.db.models import DelegatedExecutionGrant, OAuthClient, OrganizationMembership, User
from app.services import delegated_execution_service

ARTIFACT_AUDIENCE = "omnibioai-artifact-manager"
DELEGATION_SCOPE = "artifact.delegate"
PROMOTE_PERMISSION = "artifact.promote"
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,255}")


def _scopes(payload, client) -> set[str]:
    return set(payload.get("scopes") or []) & set(client.scopes or [])


def issue(db: Session, *, service_token: str, initiating_token: str, organization_id: int,
          project_id: str, run_id: str, output_ids: list[str], permissions: list[str],
          audience: str) -> tuple[str, DelegatedExecutionGrant]:
    service_payload, service = delegated_execution_service._active_service(
        db, service_token, DELEGATION_SCOPE,
    )
    if audience != ARTIFACT_AUDIENCE:
        raise HTTPException(400, "Unsupported delegation audience")
    if permissions != [PROMOTE_PERMISSION]:
        raise HTTPException(400, "Unsupported delegated permission")
    if str(service.organization_id) != str(organization_id):
        raise HTTPException(403, "Delegation context unavailable")
    identifiers = [str(project_id), str(run_id), *(str(value) for value in output_ids)]
    if (not output_ids or len(set(output_ids)) != len(output_ids) or
            any(not _IDENTIFIER.fullmatch(value) for value in identifiers)):
        raise HTTPException(400, "Invalid Artifact delegation scope")
    scopes = _scopes(service_payload, service)
    if not {DELEGATION_SCOPE, PROMOTE_PERMISSION} <= scopes:
        raise HTTPException(403, "Service delegation not authorized")
    user, membership = delegated_execution_service._user_membership(db, initiating_token, organization_id)
    if PROMOTE_PERMISSION not in delegated_execution_service._user_permissions(user, membership):
        raise HTTPException(403, "Delegated permission denied")
    delegation_id = str(uuid.uuid4())
    grant = DelegatedExecutionGrant(
        delegation_id=delegation_id, client_id=service.client_id, user_id=user.id,
        organization_id=organization_id, permissions=[PROMOTE_PERMISSION], audience=audience,
        project_id=str(project_id), run_id=str(run_id), output_ids=sorted(output_ids),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.DELEGATED_EXECUTION_TOKEN_EXPIRE_MINUTES),
    )
    db.add(grant)
    db.commit()
    token = create_artifact_delegation_token(
        client_id=service.client_id, user_id=user.id, organization_id=organization_id,
        project_id=str(project_id), run_id=str(run_id), output_ids=output_ids,
        delegation_id=delegation_id,
    )
    return token, grant


def introspect(db: Session, token: str) -> dict | None:
    try:
        payload = decode_token_for_audience(token, ARTIFACT_AUDIENCE)
        if payload.get("type") != "artifact_delegation":
            return None
        if (payload.get("iss") != settings.JWT_ISSUER or
                payload.get("aud") != ARTIFACT_AUDIENCE or
                type(payload.get("exp")) is not int):
            return None
        delegation_id = str(payload["delegation_id"])
        if payload.get("jti") != delegation_id:
            return None
        assert_token_usable(payload, db)
        grant = db.query(DelegatedExecutionGrant).filter(
            DelegatedExecutionGrant.delegation_id == delegation_id,
            DelegatedExecutionGrant.revoked_at.is_(None),
        ).first()
        if grant is None or grant.expires_at < datetime.utcnow() or grant.audience != ARTIFACT_AUDIENCE:
            return None
        expected = {
            "client_id": grant.client_id, "sub": str(grant.user_id),
            "org_id": str(grant.organization_id), "project_id": grant.project_id,
            "run_id": grant.run_id,
        }
        if any(str(payload.get(key)) != str(value) for key, value in expected.items()):
            return None
        if (payload.get("permissions") != [PROMOTE_PERMISSION] or
                sorted(payload.get("output_ids") or []) != sorted(grant.output_ids or [])):
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
        if str(client.organization_id) != str(grant.organization_id):
            return None
        if client.expires_at and client.expires_at < datetime.utcnow():
            return None
        if not {DELEGATION_SCOPE, PROMOTE_PERMISSION} <= set(client.scopes or []):
            return None
        if PROMOTE_PERMISSION not in delegated_execution_service._user_permissions(user, membership):
            return None
        return {
            "issuer": settings.JWT_ISSUER, "client_id": grant.client_id,
            "user_id": str(grant.user_id), "organization_id": str(grant.organization_id),
            "project_id": grant.project_id, "run_id": grant.run_id,
            "output_ids": list(grant.output_ids or []), "permissions": [PROMOTE_PERMISSION],
            "delegation_id": delegation_id,
        }
    except Exception:
        return None
