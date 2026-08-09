"""Phase 4 PR-A (Session Foundation): self-service session management --
"which of my logins are still active, and let me kill one from here."

Bare `get_current_user`, no permission required -- same shape
routes_mfa.py's `/users/me/mfa` already uses for own-account-only data
(see that module's docstring). Every query below is filtered on the
caller's own `user_id`; there is no cross-user or cross-org listing here
-- an org-scoped/platform-admin view (`GET /orgs/{org_id}/sessions`,
`GET /platform/sessions`, matching `routes_platform_audit.py`'s existing
gating convention) is left for the Control Center integration PR, not
built here (see docs/session-foundation-discovery.md).

Mounted at `/sessions` rather than `/users/me/sessions` -- the one
deliberate departure from this repo's own self-service URL convention --
because `/sessions`, `/sessions/{id}`, and `/sessions/{id}/revoke` are
the exact paths the platform's Sessions & Interactions architecture
report already specified for Control Center's future proxy to target
1:1; matching that contract now avoids a rename later.

Never returns a raw refresh token, access token, or any other secret --
see app/schemas/session.py's `SessionOut` for the complete, deliberately
small field list, and app/db/models.py::UserSession's own docstring for
why no such field exists on the underlying row to begin with.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import UserSession
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.session import SessionOut
from app.services import auth_service, session_service

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _serialize(session: UserSession) -> SessionOut:
    return SessionOut(
        session_id=session.session_id,
        organization_id=session.organization_id,
        auth_method=session.auth_method,
        mfa_verified=session.mfa_verified,
        status=session_service.effective_status(session),
        created_at=session.created_at,
        last_activity_at=session.last_activity_at,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
        revoked_reason=session.revoked_reason,
        client_ip=session.client_ip,
        user_agent=session.user_agent,
    )


@router.get("", response_model=list[SessionOut])
def list_my_sessions(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(UserSession)
        .filter(UserSession.user_id == int(user["sub"]))
        .order_by(UserSession.created_at.desc())
        .all()
    )
    return [_serialize(row) for row in rows]


@router.get("/{session_id}", response_model=SessionOut)
def get_my_session(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    row = (
        db.query(UserSession)
        .filter(UserSession.session_id == session_id, UserSession.user_id == int(user["sub"]))
        .first()
    )
    if row is None:
        # 404, not 403 -- do not confirm to a caller whether a session_id
        # belonging to someone else exists at all, same reasoning as
        # app/rbac.py::get_org_membership's own 404-not-403 choice.
        raise HTTPException(404, "Session not found")
    return _serialize(row)


@router.post("/{session_id}/revoke", response_model=SessionOut)
def revoke_my_session(session_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    row = (
        db.query(UserSession)
        .filter(UserSession.session_id == session_id, UserSession.user_id == int(user["sub"]))
        .first()
    )
    if row is None:
        raise HTTPException(404, "Session not found")

    auth_service.revoke_session(db, session_id)
    db.commit()
    db.refresh(row)
    return _serialize(row)
