from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.platform_admin import PlatformOrgDetailOut, PlatformOrgListOut
from app.services import platform_admin_service

# Phase 3 PR1. Deliberately a new, separate prefix -- /platform/orgs is a
# platform-admin-only, cross-tenant discovery view, not a variant of the
# existing per-org /orgs/{org_id} surface (routes_orgs.py), which stays
# org-membership-scoped and completely unmodified by this PR.
router = APIRouter(prefix="/platform", tags=["platform-admin"])

# Every route here requires the same global manage_all_orgs permission
# (Phase 3 PR0.4) -- require_permission, not require_org_permission_or_
# platform_admin: there is no org_id in these routes' own path to scope a
# membership check against for the list endpoint, and the detail endpoint
# deliberately does not fall back to org membership either (a platform
# admin must be able to discover an org before ever "belonging" to it in
# any sense, synthetic or real) -- see PR0.4's own rbac.py for the
# membership-based bypass this intentionally does not reuse here.
_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


@router.get("/orgs", response_model=PlatformOrgListOut)
def list_platform_organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, description="Matches organization name or owner email"),
    sort_by: Literal["name", "created_at", "status", "owner_email"] = Query("created_at"),
    sort_order: Literal["asc", "desc"] = Query("desc"),
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    items, total = platform_admin_service.list_organizations(
        db, page=page, page_size=page_size, search=search, sort_by=sort_by, sort_order=sort_order,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return PlatformOrgListOut(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.get("/orgs/{org_id}", response_model=PlatformOrgDetailOut)
def get_platform_organization(
    org_id: int,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    detail = platform_admin_service.get_organization_detail(db, org_id)
    if detail is None:
        raise HTTPException(404, "Organization not found")
    return detail
