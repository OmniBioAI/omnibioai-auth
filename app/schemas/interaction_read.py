"""PR-B5-A (Interaction Read API): response shape for the read-only
GET /platform/interactions endpoints.

Deliberately a separate module from app/schemas/interaction.py --
InteractionEvent there is the write/producer contract (interaction_id/
timestamp minted via default_factory, consumed by build_interaction_event/
persist_interaction). This module is the read side of an already-persisted
row, with no default_factory fields and no relationship to event
construction, mirroring app/schemas/audit.py's own AuditEventOut/
AuditEventListOut split from AuditEvent's write path -- the same
convention every other read/write pair in this codebase already follows.

Mirrors AuditEventListOut's pagination shape exactly (items/total/page/
page_size/total_pages), the same convention every /platform/* list
endpoint in this codebase already uses.
"""
from datetime import datetime

from pydantic import BaseModel


class InteractionOut(BaseModel):
    id: int
    interaction_id: str
    organization_id: int
    user_id: int | None
    session_id: str | None
    trace_id: str | None
    service: str
    interaction_type: str
    action: str
    resource_type: str | None
    resource_id: str | None
    status: str | None
    decision: str | None
    # Exposed as `metadata` in the API, matching AuditEventOut's identical
    # rename of the same underlying pattern -- the DB/ORM attribute is
    # `event_metadata` (Python can't call it `metadata`, reserved by
    # SQLAlchemy's declarative Base; see Interaction's own model
    # docstring), but there is no such reservation at the API/Pydantic
    # layer, so the response uses the name that actually describes it.
    metadata: dict | None
    created_at: datetime


class InteractionListOut(BaseModel):
    items: list[InteractionOut]
    total: int
    page: int
    page_size: int
    total_pages: int
