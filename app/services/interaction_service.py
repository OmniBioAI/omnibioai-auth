"""PR-B2 (Interactions Foundation): the single choke point for creating,
persisting, and publishing Interaction events.

Every future producer (RAG in PR-B3, and whatever follows) must go
through `create_interaction`/`build_interaction_event` here -- never
hand-build an `interactions:events` payload independently. This is the
exact class of problem PR-B1 investigated in the Gateway -> Security
Audit path (a payload shape that drifted from its consumer's contract
because multiple call sites built it by hand); this module exists so
that mistake has nowhere to happen for Interactions.

Architecture decision, made explicit here per this PR's own brief
(Section 31): PR-B2 does NOT include a Redis consumer/worker. Unlike
omnibioai-security-audit, this repo has no existing worker/consumer/
Dockerfile.worker infrastructure to reuse, and building one from scratch
is a materially larger, separately-reviewable change than "foundation."
`persist_interaction` below performs the actual durable write directly
against this service's own database -- the exact same shape
app/services/audit_service.py::log_event already uses for its own local
ledger (AuditEvent) -- so the `interactions` table is authoritative and
consistent the moment this call returns, without depending on any
future consumer ever being built. `publish_interaction` is a parallel,
best-effort signal from the same already-built event, for any future
external consumer (a later PR, decided separately) to pick up -- it is
never what makes this service's own table correct.

Fail-open throughout, matching every adjacent convention in this
codebase: app/core/token_revocation.py's Redis blacklist check,
app/services/session_service.py's "never break the caller" module
docstring, and app/services/audit_service.py::log_event's own
try/except-rollback-log shape. An Interaction is telemetry/analytics
data, not an authorization decision -- losing one must never fail the
real request that produced it. This mirrors omnibioai-security-audit's
own fail-open policy, but is not copied blindly: it was independently
re-derived from this repo's own established behavior for exactly this
question, and would be revisited if Interactions ever became load-
bearing for a security/authorization decision (they are not, today).
"""
import json
import logging
import os

import redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import Interaction
from app.schemas.interaction import InteractionEvent

logger = logging.getLogger("omnibioai.auth.interactions")

STREAM = "interactions:events"
MAX_STREAM_LENGTH = int(os.getenv("INTERACTIONS_MAXLEN", "1000000"))

# Same env var/default api-gateway's/security-audit's REDIS_URL and this
# repo's own app/core/token_revocation.py already use -- already wired
# into auth-service's compose environment (REDIS_URL: redis://redis:6379),
# no omnibioai-studio change required.
_redis = redis.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"), decode_responses=True
)

# Deny-list of metadata key *names* that must never carry a value into a
# durably-stored Interaction -- defense in depth on top of "producers
# should simply never put this there" (Section 15). Matched
# case-insensitively against dict keys, including nested dicts, since
# `metadata` is caller-supplied free-form JSON and this is the one place
# every Interaction, regardless of producer, passes through.
_FORBIDDEN_METADATA_KEY_SUBSTRINGS = (
    "token", "secret", "password", "cookie", "authorization",
    "credential", "api_key", "apikey", "private_key",
)


def _redact_metadata(metadata: dict | None) -> dict:
    """Strips any key whose name looks secret-shaped, recursively.
    Never raises; a malformed/unexpected metadata shape is logged and
    replaced with an empty dict rather than blocking the Interaction."""
    if not metadata:
        return {}
    try:
        cleaned: dict = {}
        for key, value in metadata.items():
            key_lower = str(key).lower()
            if any(bad in key_lower for bad in _FORBIDDEN_METADATA_KEY_SUBSTRINGS):
                logger.warning("interaction_metadata_redacted key=%s", key)
                continue
            cleaned[key] = _redact_metadata(value) if isinstance(value, dict) else value
        return cleaned
    except Exception:
        logger.exception("interaction_metadata_redaction_failed")
        return {}


def build_interaction_event(
    *,
    organization_id: int,
    service: str,
    interaction_type: str,
    action: str = "",
    user_id: int | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    status: str | None = None,
    decision: str | None = None,
    metadata: dict | None = None,
) -> InteractionEvent:
    """Builds one Interaction event -- `interaction_id`/`timestamp`
    generated here, once (InteractionEvent's own `default_factory`
    fields), at the moment the logical Interaction is created. The
    caller must reuse the returned object for both persistence and
    publishing (create_interaction below does this automatically) --
    never call this twice for what is logically the same event, or it
    stops being idempotent by construction.
    """
    return InteractionEvent(
        organization_id=organization_id,
        user_id=user_id,
        session_id=session_id,
        trace_id=trace_id,
        service=service,
        interaction_type=interaction_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        decision=decision,
        metadata=_redact_metadata(metadata),
    )


def persist_interaction(db: Session, event: InteractionEvent) -> Interaction | None:
    """Durably writes `event` as one `interactions` row. Idempotent on
    `interaction_id`: redelivering/retrying the same event is a safe
    no-op that returns the already-persisted row, never a duplicate --
    same IntegrityError-catch convention omnibioai-security-audit's
    consumers/sink.py::Sink.write already established for event_id.

    Never raises -- mirrors audit_service.log_event exactly. Returns
    None only on a genuine, non-duplicate persistence failure (rolled
    back and logged); the caller already has the event's interaction_id
    regardless, from build_interaction_event's return value.
    """
    record = Interaction(
        interaction_id=event.interaction_id,
        organization_id=event.organization_id,
        user_id=event.user_id,
        session_id=event.session_id,
        trace_id=event.trace_id,
        service=event.service,
        interaction_type=event.interaction_type,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        status=event.status,
        decision=event.decision,
        event_metadata=event.metadata,
        created_at=event.timestamp,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except IntegrityError:
        # interaction_id already present -- a durable copy already
        # exists (e.g. a caller retry after an ambiguous failure).
        # Treat as success, not a failure to retry, and hand back the
        # pre-existing row rather than nothing.
        db.rollback()
        return (
            db.query(Interaction)
            .filter(Interaction.interaction_id == event.interaction_id)
            .first()
        )
    except Exception:
        logger.exception(
            "interaction_persist_failed interaction_id=%s", event.interaction_id
        )
        db.rollback()
        return None


def publish_interaction(event: InteractionEvent) -> None:
    """Best-effort publish of `event` to `interactions:events`. Never
    raises -- fail-open, matching app/core/token_revocation.py's Redis
    convention in this same repo. Not what makes an Interaction durable
    (see this module's own docstring) -- a Redis outage never blocks or
    invalidates the DB write persist_interaction already performed.
    """
    try:
        _redis.xadd(
            STREAM,
            {"data": event.model_dump_json()},
            maxlen=MAX_STREAM_LENGTH,
            approximate=True,
        )
    except Exception:
        logger.warning(
            "interaction_publish_failed interaction_id=%s", event.interaction_id
        )


def create_interaction(
    db: Session,
    *,
    organization_id: int,
    service: str,
    interaction_type: str,
    action: str = "",
    user_id: int | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    status: str | None = None,
    decision: str | None = None,
    metadata: dict | None = None,
) -> InteractionEvent:
    """Convenience wrapper for the common case: build once, persist,
    publish. Returns the built event (always has a stable
    interaction_id/timestamp, regardless of whether persistence or
    publishing individually succeeded) -- not the ORM row, so callers
    never hold a session-attached object past this function's own
    commit/rollback.
    """
    event = build_interaction_event(
        organization_id=organization_id,
        service=service,
        interaction_type=interaction_type,
        action=action,
        user_id=user_id,
        session_id=session_id,
        trace_id=trace_id,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        decision=decision,
        metadata=metadata,
    )
    persist_interaction(db, event)
    publish_interaction(event)
    return event
