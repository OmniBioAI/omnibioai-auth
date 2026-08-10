"""PR-B5-A (Interaction Read API): read-only retrieval for the
`interactions` table PR-B2 created and PR-B3/PR-B4 populate.

No new permission: reuses MANAGE_ALL_ORGS, the same platform-admin
boundary routes_platform_audit.py already established for the closely
analogous AuditEvent ledger -- "see every organization's interactions" is
squarely within what that permission already means, same reasoning as
that route's own comment.

GET only -- no PATCH/PUT/DELETE. Interactions are a durable ledger,
written exclusively via interaction_service.persist_interaction (direct)
or app/workers/interaction_consumer.py (via Redis); this file adds no
second write path and no mutation of any kind.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.interaction_read import InteractionListOut, InteractionOut
from app.services import interaction_query_service

# Same prefix/tag convention routes_platform_audit.py (and routes_platform_
# users.py/routes_platform_roles.py/routes_platform_permissions.py before
# it) already established for this family of platform-admin-only surfaces.
router = APIRouter(prefix="/platform", tags=["platform-admin"])

_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


def _out(interaction) -> InteractionOut:
    return InteractionOut(
        id=interaction.id,
        interaction_id=interaction.interaction_id,
        organization_id=interaction.organization_id,
        user_id=interaction.user_id,
        session_id=interaction.session_id,
        trace_id=interaction.trace_id,
        service=interaction.service,
        interaction_type=interaction.interaction_type,
        action=interaction.action,
        resource_type=interaction.resource_type,
        resource_id=interaction.resource_id,
        status=interaction.status,
        decision=interaction.decision,
        metadata=interaction.event_metadata,
        created_at=interaction.created_at,
    )


@router.get("/interactions", response_model=InteractionListOut)
def list_interactions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    organization_id: int | None = Query(None),
    user_id: int | None = Query(None),
    service: str | None = Query(None),
    interaction_type: str | None = Query(None),
    status: str | None = Query(None),
    start_date: datetime | None = Query(None),
    end_date: datetime | None = Query(None),
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    interactions, total = interaction_query_service.list_interactions(
        db, page=page, page_size=page_size, organization_id=organization_id,
        user_id=user_id, service=service, interaction_type=interaction_type,
        status=status, start_date=start_date, end_date=end_date,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return InteractionListOut(
        items=[_out(i) for i in interactions],
        total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


@router.get("/interactions/{interaction_id}", response_model=InteractionOut)
def get_interaction(
    interaction_id: str,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    interaction = interaction_query_service.get_interaction(db, interaction_id)
    if interaction is None:
        raise HTTPException(404, "Interaction not found")
    return _out(interaction)
