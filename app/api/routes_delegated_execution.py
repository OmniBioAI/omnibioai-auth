from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.schemas.delegated_execution import (
    DelegatedExecutionIntrospectionOut,
    DelegatedExecutionIntrospectionRequest,
    DelegatedExecutionTokenOut,
    DelegatedExecutionTokenRequest,
)
from app.services import audit_service, delegated_execution_service

router = APIRouter(prefix="/service/delegations", tags=["delegated-execution"])
_bearer = HTTPBearer()


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
