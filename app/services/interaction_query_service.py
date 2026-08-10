"""PR-B5-A (Interaction Read API): read side of the `interactions` table.

A separate module from app/services/interaction_service.py -- that module
is the single write choke point (build_interaction_event/persist_interaction/
publish_interaction/create_interaction, per its own module docstring) for
every future producer/consumer to go through; this module adds nothing to
that write path and duplicates none of its persistence logic. Mirrors
app/services/audit_service.py's own read-side addition (list_events),
added there rather than a separate module for the identical reason that
module's own comment gives -- kept separate here instead only because
interaction_service.py's docstring is explicit that it is the write choke
point, and a read/write split keeps that guarantee legible rather than
implicit.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import Interaction


def list_interactions(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    organization_id: int | None = None,
    user_id: int | None = None,
    service: str | None = None,
    interaction_type: str | None = None,
    status: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[Interaction], int]:
    """Returns (page of interactions, total matching) -- same (items, total)
    tuple contract audit_service.list_events already uses, so this
    endpoint's pagination math mirrors routes_platform_audit.py's exactly.
    All filters optional and AND-combined; an omitted filter matches
    everything, same convention list_events's own filters already follow.
    Newest first -- created_at DESC, id DESC as a tiebreaker for
    interactions written in the same microsecond (SQLite/some backends'
    datetime resolution isn't always fine enough to order same-transaction
    rows by created_at alone), identical reasoning to list_events's own
    tiebreaker.
    """
    query = db.query(Interaction)
    if organization_id is not None:
        query = query.filter(Interaction.organization_id == organization_id)
    if user_id is not None:
        query = query.filter(Interaction.user_id == user_id)
    if service:
        query = query.filter(Interaction.service == service)
    if interaction_type:
        query = query.filter(Interaction.interaction_type == interaction_type)
    if status:
        query = query.filter(Interaction.status == status)
    if start_date is not None:
        query = query.filter(Interaction.created_at >= start_date)
    if end_date is not None:
        query = query.filter(Interaction.created_at <= end_date)

    total = query.count()
    interactions = (
        query.order_by(Interaction.created_at.desc(), Interaction.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return interactions, total


def get_interaction(db: Session, interaction_id: str) -> Interaction | None:
    """Single-record lookup by the existing unique `interaction_id` --
    the same column persist_interaction's own idempotency already relies
    on (PR-B2), not a new identity concept."""
    return db.query(Interaction).filter(Interaction.interaction_id == interaction_id).first()
