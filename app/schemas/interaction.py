"""PR-B2 (Interactions Foundation): the canonical Interaction event shape.

One Pydantic model serves both roles -- the validated event envelope
published to Redis (`interactions:events`) and the source of the fields
written to the `interactions` table -- so there is exactly one place
this repo defines what an Interaction event looks like, mirroring
omnibioai-security-audit's `audit/models.py::AuditEvent` (a proven,
already-shipped instance of this same "one Pydantic model, both roles"
pattern) rather than inventing a second convention.

interaction_id/timestamp use `default_factory`, exactly like AuditEvent's
own event_id/timestamp fields -- generated once, when the model instance
is created (app/services/interaction_service.py::build_interaction_event
is the single call site that ever constructs one), never regenerated on
retry or re-serialization. See that module for why this is essential for
idempotency.

organization_id/user_id are plain `int`, matching this repo's actual
schema convention (every model's PK/FK is Integer, not UUID -- see
app/db/models.py::Interaction's own docstring), not the generic
"UUID/string" placeholder an earlier draft of this brief used before
discovery confirmed the real convention.
"""
import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class InteractionEvent(BaseModel):
    interaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    # Naive UTC, matching every other timestamp in this schema
    # (datetime.utcnow() convention -- see Interaction model's docstring
    # for why this deliberately does not introduce the only
    # timezone-aware column in the database).
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    organization_id: int
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None

    service: str
    interaction_type: str
    action: str = ""

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None

    status: Optional[str] = None
    decision: Optional[str] = None

    # Non-secret structured context only -- see interaction_service.py's
    # module docstring for the redaction rule this field must never
    # violate (no tokens, cookies, authorization headers, passwords, or
    # other secret-shaped values).
    metadata: dict[str, Any] = {}
