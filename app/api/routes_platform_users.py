from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, get_current_user, require_permission
from app.schemas.user_admin import PlatformUserDetailOut, PlatformUserListOut, UserStatusUpdate
from app.services import user_admin_service

# Phase 3 PR3A. New prefix, mirroring routes_platform_admin.py's own
# /platform/orgs shape exactly -- /platform/users is a platform-admin-only,
# cross-tenant user directory, unrelated to the empty, unregistered
# routes_users.py stub (whatever that was originally meant to become is a
# different, self-service concern, not touched by this PR).
router = APIRouter(prefix="/platform/users", tags=["platform-admin"])

# Same manage_all_orgs permission PR1's org directory and PR0.4's org
# bypass already use -- deliberately not a new, narrower permission (e.g.
# "manage_all_users"). platform_admin is treated here as one general
# cross-tenant capability, matching how ~/phase3_design.md's own blueprint
# describes it, not split into a new permission per resource type. See
# this PR's implementation report for the tradeoff this accepts.
_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


@router.get("", response_model=PlatformUserListOut)
def list_platform_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, description="Matches user email"),
    # PR11.1: all three additive and independently optional -- an
    # omitted param behaves exactly as it did before this PR (backward
    # compatible), see user_admin_service.list_users for how they combine.
    organization_id: int | None = Query(None),
    status: str | None = Query(None),
    role: str | None = Query(None),
    sort_by: Literal["email", "created_at", "status"] = Query("created_at"),
    sort_order: Literal["asc", "desc"] = Query("desc"),
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    items, total = user_admin_service.list_users(
        db, page=page, page_size=page_size, search=search, sort_by=sort_by, sort_order=sort_order,
        organization_id=organization_id, status=status, role=role,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return PlatformUserListOut(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.get("/{user_id}", response_model=PlatformUserDetailOut)
def get_platform_user(
    user_id: int,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    detail = user_admin_service.get_user_detail(db, user_id)
    if detail is None:
        raise HTTPException(404, "User not found")
    return detail


@router.patch("/{user_id}", response_model=PlatformUserDetailOut)
def update_platform_user_status(
    user_id: int,
    body: UserStatusUpdate,
    db: Session = Depends(get_db),
    caller=Depends(get_current_user),
    _admin=Depends(_require_platform_admin),
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(404, "User not found")

    try:
        user_admin_service.set_user_status(
            db, target, body.status, body.reason, actor_user_id=int(caller["sub"])
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    detail = user_admin_service.get_user_detail(db, user_id)
    return detail
