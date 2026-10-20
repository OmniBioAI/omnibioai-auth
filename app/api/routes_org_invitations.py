"""Public token operations for organization invitation acceptance.

Only the opaque token enters these request bodies (never URL paths or query
strings), keeping reverse-proxy access logs free of bearer invitation data.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.orgs import InvitationAcceptRequest, InvitationExistingAcceptRequest, InvitationTokenRequest
from app.services import org_invitation_service
from app.services.org_invitation_service import OrganizationInvitationError
from app.services import audit_service
from app.services.audit_service import AuditEventType

router = APIRouter(prefix="/organization-invitations", tags=["organization-invitations"])


def _throttle(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    # Namespaced fixed-window lock keys. Redis failure uses the existing
    # bounded in-process fallback policy from the shared Auth limiter.
    key = str(client)[:128]
    result = rate_limit.record_attempt(
        f"org-invite:fail:{key}", f"org-invite:lock:{key}",
        window_seconds=900, max_attempts=30, lockout_seconds=900,
        fallback_window_seconds=900, fallback_max_attempts=20,
    )
    if result.locked:
        raise HTTPException(429, "Too many invitation attempts; try again later")


def _call(db: Session, call, actor_user_id: int | None = None):
    try:
        return call()
    except OrganizationInvitationError as exc:
        audit_service.log_event(
            db, AuditEventType.ORG_INVITATION_DENIED, actor_user_id=actor_user_id,
            resource_type="organization_invitation",
            metadata={"reason": exc.code},
        )
        raise HTTPException(exc.status_code, {"code": exc.code, "detail": str(exc)}) from None


@router.post("/preview")
def preview_invitation(body: InvitationTokenRequest, request: Request, db: Session = Depends(get_db)):
    _throttle(request)
    return _call(db, lambda: org_invitation_service.preview_invitation(db, body.token))


@router.post("/mfa-setup")
def invitation_mfa_setup(body: InvitationTokenRequest, request: Request, db: Session = Depends(get_db)):
    _throttle(request)
    return _call(db, lambda: org_invitation_service.start_invitation_mfa(db, body.token))


@router.post("/accept")
def accept_invitation(body: InvitationAcceptRequest, request: Request, db: Session = Depends(get_db)):
    _throttle(request)
    return _call(db, lambda: org_invitation_service.accept_new_user(
        db, token=body.token, password=body.password, totp_code=body.totp_code,
    ))


@router.post("/accept-existing")
def accept_existing_invitation(
    body: InvitationExistingAcceptRequest,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _throttle(request)
    account = db.query(org_invitation_service.User).filter(
        org_invitation_service.User.id == int(user["sub"])
    ).first()
    if account is None:
        raise HTTPException(401, "Invalid user")
    return _call(db, lambda: org_invitation_service.accept_existing_user(
        db, token=body.token, user=account, totp_code=body.totp_code,
    ), actor_user_id=account.id)
