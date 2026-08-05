"""PR11.4b (Identity Audit Trail Foundation): the one read-only
retrieval endpoint this PR adds. No retrieval API existed before this
PR (confirmed by discovery -- see docs/pr11-identity-audit-discovery.md
in omnibioai-control-center, written before this file was added).

Immutability is structural, not a convention: this file defines GET
only. No PATCH/DELETE on audit events exists anywhere in this codebase,
and none should ever be added -- an audit ledger that can be edited or
removed after the fact isn't one.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.audit import AuditEventListOut, AuditEventOut
from app.services import audit_service

# Same prefix/tag convention routes_platform_users.py, routes_platform_
# roles.py, and routes_platform_permissions.py already established for
# this family of platform-admin-only surfaces.
router = APIRouter(prefix="/platform", tags=["platform-admin"])

# Reuses the existing platform-admin permission (Phase 3 PR0.4) rather
# than introducing a dedicated audit permission -- no such permission is
# registered anywhere in app/core/permission_names.py today, and the
# task this PR implements explicitly says not to add one unless
# required. manage_all_orgs is the same boundary every other
# /platform/* read endpoint in this codebase already uses; "see every
# organization's audit trail" is squarely within what that permission
# already means. A platform admin reading another organization's events
# is exactly the intended use, not a gap -- see this route's own
# metadata: the *reader's* identity is unrelated to whether a *written*
# event captured organization context correctly (that's each log_event
# call site's job, unchanged by who later queries it).
_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


@router.get("/audit-events", response_model=AuditEventListOut)
def list_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    organization_id: int | None = Query(None),
    actor_user_id: int | None = Query(None),
    event_type: str | None = Query(None),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    db=Depends(get_db),
    user=Depends(_require_platform_admin),
):
    events, total = audit_service.list_events(
        db, page=page, page_size=page_size, organization_id=organization_id,
        actor_user_id=actor_user_id, event_type=event_type, start_date=start_date, end_date=end_date,
    )
    display = audit_service.resolve_display_fields(db, events)

    items = [
        AuditEventOut(
            id=e.id, event_type=e.event_type,
            actor_user_id=e.actor_user_id, actor_email=display[e.id]["actor_email"],
            target_user_id=e.target_user_id, target_email=display[e.id]["target_email"],
            organization_id=e.organization_id, organization_name=display[e.id]["organization_name"],
            resource_type=e.resource_type, resource_id=e.resource_id,
            before_state=e.before_state, after_state=e.after_state,
            metadata=e.event_metadata, created_at=e.created_at,
        )
        for e in events
    ]
    total_pages = (total + page_size - 1) // page_size if total else 0
    return AuditEventListOut(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)
