"""
OmniBioAI app.api.routes_delegated_execution.

Purpose:
    Defines HTTP route handlers for app.api.routes_delegated_execution, including issue_toolserver_delegation, introspect_toolserver_delegation, issue_toolserver_registration and introspect_toolserver_registration.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.session import get_db
from app.schemas.delegated_execution import (
    ArtifactDelegationIntrospectionOut,
    ArtifactDelegationTokenRequest,
    ArtifactEntitlementContextRequest,
    DelegatedExecutionIntrospectionOut,
    DelegatedExecutionIntrospectionRequest,
    DelegatedExecutionTokenOut,
    DelegatedExecutionTokenRequest,
    ToolServerRegistrationIntrospectionOut,
    ToolServerRegistrationTokenOut,
)
from app.services import (
    artifact_delegation_service,
    artifact_entitlement_service,
    audit_service,
    delegated_execution_service,
    toolserver_registration_service,
)

router = APIRouter(prefix="/service/delegations", tags=["delegated-execution"])
_bearer = HTTPBearer()


@router.post("/artifact/entitlement-context")
def artifact_entitlement_context(
    body: ArtifactEntitlementContextRequest,
    caller: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
):
    # No owner/plan/organization override is accepted by this boundary.
    try:
        identity = artifact_entitlement_service.context(
            db, service_token=caller.credentials, artifact_token=body.token,
        )
    except HTTPException as exc:
        audit_service.log_event(
            db, audit_service.AuditEventType.ARTIFACT_ENTITLEMENT_CONTEXT_DENIED,
            resource_type="artifact_entitlement", metadata={"status": exc.status_code},
            commit=False,
        )
        db.commit()
        raise
    audit_service.log_event(
        db, audit_service.AuditEventType.ARTIFACT_ENTITLEMENT_CONTEXT_ALLOWED,
        target_user_id=int(identity["user_id"]), organization_id=int(identity["organization_id"]),
        resource_type="artifact_entitlement", resource_id=identity["delegation_id"],
        metadata={"service_client_id": identity["service_client_id"],
                  "project_id": identity["project_id"], "run_id": identity["run_id"]},
        commit=False,
    )
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(503, "Artifact entitlement audit unavailable") from None
    return identity


@router.post("/artifact", response_model=DelegatedExecutionTokenOut)
def issue_artifact_delegation(
    body: ArtifactDelegationTokenRequest,
    request: Request,
    caller: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
):
    trace_id = request.headers.get("x-request-id") or request.headers.get("x-trace-id")
    try:
        token, grant = artifact_delegation_service.issue(
            db, service_token=caller.credentials, initiating_token=body.initiating_token,
            organization_id=body.organization_id, project_id=body.project_id,
            run_id=body.run_id, output_ids=body.output_ids,
            permissions=body.permissions, audience=body.audience,
        )
    except HTTPException as exc:
        audit_service.log_event(
            db, audit_service.AuditEventType.DELEGATED_EXECUTION_TOKEN_DENIED,
            organization_id=body.organization_id,
            metadata={"audience": body.audience, "project_id": body.project_id,
                      "run_id": body.run_id, "reason": str(exc.detail), "trace_id": trace_id},
        )
        raise
    audit_service.log_event(
        db, audit_service.AuditEventType.DELEGATED_EXECUTION_TOKEN_ISSUED,
        actor_user_id=grant.user_id, target_user_id=grant.user_id,
        organization_id=grant.organization_id, resource_type="artifact_delegation",
        resource_id=grant.delegation_id,
        metadata={"client_id": grant.client_id, "audience": grant.audience,
                  "project_id": grant.project_id, "run_id": grant.run_id,
                  "output_ids": grant.output_ids, "delegation_id": grant.delegation_id,
                  "trace_id": trace_id},
    )
    return DelegatedExecutionTokenOut(
        access_token=token,
        expires_in=settings.DELEGATED_EXECUTION_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/artifact/introspect", response_model=ArtifactDelegationIntrospectionOut)
def introspect_artifact_delegation(
    body: DelegatedExecutionIntrospectionRequest,
    db: Session = Depends(get_db),  # noqa: B008
):
    identity = artifact_delegation_service.introspect(db, body.token)
    return ArtifactDelegationIntrospectionOut(valid=identity is not None, **(identity or {}))


@router.post("/toolserver", response_model=DelegatedExecutionTokenOut)
def issue_toolserver_delegation(
    body: DelegatedExecutionTokenRequest,
    request: Request,
    caller: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
):
    try:
        token, grant = delegated_execution_service.issue(
            db,
            service_token=caller.credentials,
            initiating_token=body.initiating_token,
            organization_id=body.organization_id,
            permissions=body.permissions,
            audience=body.audience,
        )
    except HTTPException as exc:
        audit_service.log_event(
            db,
            audit_service.AuditEventType.DELEGATED_EXECUTION_TOKEN_DENIED,
            organization_id=body.organization_id,
            metadata={
                "audience": body.audience,
                "permissions": sorted(set(body.permissions)),
                "reason": str(exc.detail),
                "trace_id": request.headers.get("x-request-id") or request.headers.get("x-trace-id"),
            },
        )
        raise
    audit_service.log_event(
        db,
        audit_service.AuditEventType.DELEGATED_EXECUTION_TOKEN_ISSUED,
        actor_user_id=grant.user_id,
        target_user_id=grant.user_id,
        organization_id=grant.organization_id,
        resource_type="delegated_execution",
        resource_id=grant.delegation_id,
        metadata={
            "client_id": grant.client_id,
            "audience": grant.audience,
            "permissions": grant.permissions,
            "delegation_id": grant.delegation_id,
            "trace_id": request.headers.get("x-request-id") or request.headers.get("x-trace-id"),
        },
    )
    return DelegatedExecutionTokenOut(
        access_token=token,
        expires_in=settings.DELEGATED_EXECUTION_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/toolserver/introspect", response_model=DelegatedExecutionIntrospectionOut)
def introspect_toolserver_delegation(
    body: DelegatedExecutionIntrospectionRequest,
    db: Session = Depends(get_db),  # noqa: B008
):
    identity = delegated_execution_service.introspect(db, body.token)
    return DelegatedExecutionIntrospectionOut(valid=identity is not None, **(identity or {}))


# Service-only registration credential (TES startup -> ToolServer
# /register_tools). No user principal: see
# app/services/toolserver_registration_service.py for why this is separate
# from the delegation endpoints above rather than a mode of them.
@router.post("/toolserver/registration", response_model=ToolServerRegistrationTokenOut)
def issue_toolserver_registration(
    request: Request,
    caller: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
):
    trace_id = request.headers.get("x-request-id") or request.headers.get("x-trace-id")
    try:
        token, client, registration_id = toolserver_registration_service.issue(db, service_token=caller.credentials)
    except HTTPException as exc:
        audit_service.log_event(
            db,
            audit_service.AuditEventType.TOOLSERVER_REGISTRATION_TOKEN_DENIED,
            metadata={"audience": toolserver_registration_service.TOOLSERVER_AUDIENCE,
                      "reason": str(exc.detail), "trace_id": trace_id},
        )
        raise
    audit_service.log_event(
        db,
        audit_service.AuditEventType.TOOLSERVER_REGISTRATION_TOKEN_ISSUED,
        organization_id=client.organization_id,
        resource_type="toolserver_registration",
        resource_id=registration_id,
        metadata={"client_id": client.client_id,
                  "audience": toolserver_registration_service.TOOLSERVER_AUDIENCE,
                  "scopes": [toolserver_registration_service.REGISTRATION_SCOPE],
                  "registration_id": registration_id, "trace_id": trace_id},
    )
    return ToolServerRegistrationTokenOut(
        access_token=token,
        expires_in=settings.TOOLSERVER_REGISTRATION_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/toolserver/registration/introspect", response_model=ToolServerRegistrationIntrospectionOut)
def introspect_toolserver_registration(
    body: DelegatedExecutionIntrospectionRequest,
    db: Session = Depends(get_db),  # noqa: B008
):
    identity = toolserver_registration_service.introspect(db, body.token)
    return ToolServerRegistrationIntrospectionOut(valid=identity is not None, **(identity or {}))
