"""Artifact-audience delegation using the existing OAuth/grant architecture."""
from datetime import datetime, timedelta
import re
import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_artifact_delegation_token, decode_token_for_audience
from app.core.token_revocation import assert_token_usable
from app.db.models import DelegatedExecutionGrant, OAuthClient, Organization, OrganizationMembership, User
from app.services import delegated_execution_service

ARTIFACT_AUDIENCE = "omnibioai-artifact-manager"
DELEGATION_SCOPE = "artifact.delegate"
PROMOTE_PERMISSION = "artifact.promote"
DOWNLOAD_PERMISSION = "artifact.download"
_IDENTIFIER = re.compile(r"[A-Za-z0-9._:-]{1,255}")


def _scopes(payload, client) -> set[str]:
    return set(payload.get("scopes") or []) & set(client.scopes or [])


def issue(db: Session, *, service_token: str, initiating_token: str, organization_id: int,
          project_id: str, run_id: str, output_ids: list[str], permissions: list[str],
          audience: str, artifact_ids: list[str] | None = None,
          source_delegation_token: str | None = None) -> tuple[str, DelegatedExecutionGrant]:
    service_payload, service = delegated_execution_service._active_service(
        db, service_token, DELEGATION_SCOPE,
    )
    if (service_payload.get("iss") != settings.JWT_ISSUER or
            service_payload.get("aud") != settings.JWT_AUDIENCE or
            service_payload.get("type") != "access" or
            type(service_payload.get("exp")) is not int or not service_payload.get("jti") or
            "sub" in service_payload or "email" in service_payload):
        raise HTTPException(401, "Invalid service credential")
    assert_token_usable(service_payload, db)
    if audience != ARTIFACT_AUDIENCE:
        raise HTTPException(400, "Unsupported delegation audience")
    if permissions not in ([PROMOTE_PERMISSION], [DOWNLOAD_PERMISSION]):
        raise HTTPException(400, "Unsupported delegated permission")
    if str(service.organization_id) != str(organization_id):
        raise HTTPException(403, "Delegation context unavailable")
    permission = permissions[0]
    artifact_ids = artifact_ids or []
    ids = artifact_ids if permission == DOWNLOAD_PERMISSION else output_ids
    if (permission == DOWNLOAD_PERMISSION and output_ids) or (permission == PROMOTE_PERMISSION and artifact_ids):
        raise HTTPException(400, "Mixed Artifact delegation scope")
    if permission == DOWNLOAD_PERMISSION:
        try:
            if any(str(uuid.UUID(value)) != value for value in ids):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(400, "Canonical Artifact UUID required") from None
    identifiers = [str(project_id), str(run_id), *(str(value) for value in ids)]
    if (not ids or len(ids) > 100 or len(set(ids)) != len(ids) or
            any(not _IDENTIFIER.fullmatch(value) for value in identifiers)):
        raise HTTPException(400, "Invalid Artifact delegation scope")
    scopes = _scopes(service_payload, service)
    if not {DELEGATION_SCOPE, permission} <= scopes:
        raise HTTPException(403, "Service delegation not authorized")
    # General Auth decoding still admits legacy tokens without iss/aud/exp.
    # Artifact delegation must not turn such a token into a fresh capability,
    # or accept an identity whose missing jti bypasses revocation checks.
    try:
        initiating_payload = decode_token_for_audience(initiating_token, settings.JWT_AUDIENCE)
        if (initiating_payload.get("iss") != settings.JWT_ISSUER or
                initiating_payload.get("aud") != settings.JWT_AUDIENCE or
                initiating_payload.get("type") != "access" or
                initiating_payload.get("auth_method") == "client_credentials" or
                type(initiating_payload.get("exp")) is not int or
                not isinstance(initiating_payload.get("jti"), str) or
                not initiating_payload["jti"] or
                not isinstance(initiating_payload.get("sub"), str) or
                not re.fullmatch(r"[1-9][0-9]*", initiating_payload["sub"])):
            raise ValueError("Incomplete initiating identity")
    except Exception:
        raise HTTPException(403, "Invalid initiating identity") from None
    user, membership = delegated_execution_service._user_membership(db, initiating_token, organization_id)
    if not db.query(Organization).filter_by(id=organization_id, status="active").first():
        raise HTTPException(403, "Delegation context unavailable")
    if permission not in delegated_execution_service._user_permissions(user, membership):
        raise HTTPException(403, "Delegated permission denied")
    if source_delegation_token:
        source = introspect(db, source_delegation_token)
        expected = {"client_id": service.client_id, "user_id": str(user.id),
                    "organization_id": str(organization_id), "project_id": str(project_id),
                    "run_id": str(run_id), "permissions": [DOWNLOAD_PERMISSION]}
        if (permission != PROMOTE_PERMISSION or source is None or
                any(source.get(k) != v for k, v in expected.items()) or
                DOWNLOAD_PERMISSION not in set(service.scopes or [])):
            raise HTTPException(403, "Input provenance delegation denied")
        artifact_ids = source["artifact_ids"]
    delegation_id = str(uuid.uuid4())
    grant = DelegatedExecutionGrant(
        delegation_id=delegation_id, client_id=service.client_id, user_id=user.id,
        organization_id=organization_id, permissions=[permission], audience=audience,
        project_id=str(project_id), run_id=str(run_id), output_ids=sorted(output_ids),
        artifact_ids=sorted(artifact_ids),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.DELEGATED_EXECUTION_TOKEN_EXPIRE_MINUTES),
    )
    db.add(grant)
    db.commit()
    token = create_artifact_delegation_token(
        client_id=service.client_id, user_id=user.id, organization_id=organization_id,
        project_id=str(project_id), run_id=str(run_id), output_ids=output_ids,
        delegation_id=delegation_id, artifact_ids=artifact_ids, permission=permission,
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
        if grant.permissions not in ([PROMOTE_PERMISSION], [DOWNLOAD_PERMISSION]):
            return None
        permission = grant.permissions[0]
        if (payload.get("permissions") != grant.permissions or
                sorted(payload.get("artifact_ids") or []) != sorted(grant.artifact_ids or []) or
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
        if not db.query(Organization).filter_by(id=grant.organization_id, status="active").first():
            return None
        if not {DELEGATION_SCOPE, permission} <= set(client.scopes or []):
            return None
        current_permissions = delegated_execution_service._user_permissions(user, membership)
        if permission not in current_permissions:
            return None
        if grant.artifact_ids and permission == PROMOTE_PERMISSION and (
                DOWNLOAD_PERMISSION not in set(client.scopes or []) or
                DOWNLOAD_PERMISSION not in current_permissions):
            return None
        return {
            "issuer": settings.JWT_ISSUER, "client_id": grant.client_id,
            "user_id": str(grant.user_id), "organization_id": str(grant.organization_id),
            "project_id": grant.project_id, "run_id": grant.run_id,
            "output_ids": list(grant.output_ids or []), "artifact_ids": list(grant.artifact_ids or []),
            "permissions": [permission],
            "delegation_id": delegation_id,
        }
    except Exception:
        return None
