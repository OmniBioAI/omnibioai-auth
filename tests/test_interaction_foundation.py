"""PR-B2 (Interactions Foundation): the `interactions` table, its
Pydantic event contract, and the persistence side of
app/services/interaction_service.py.

Uses the same direct-DB-session pattern as tests/test_session_foundation.py
-- a second connection to the same physical sqlite file conftest.py's
`client` fixture uses -- since none of this PR's functionality is
exposed via an HTTP route (see interaction_service.py's own module
docstring for why no routes_interactions.py exists in this PR).
"""
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Interaction
from app.schemas.interaction import InteractionEvent
from app.services import interaction_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db():
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


def _row(interaction_id: str) -> Interaction | None:
    db = _DirectSession()
    try:
        return db.query(Interaction).filter(Interaction.interaction_id == interaction_id).first()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def test_interaction_id_generated():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    assert event.interaction_id


def test_interaction_id_is_valid_uuid4_format():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    parsed = uuid.UUID(event.interaction_id, version=4)
    assert str(parsed) == event.interaction_id


def test_interaction_id_stable_across_repeated_use_of_same_event():
    """The same InteractionEvent instance must carry the same
    interaction_id no matter how many times it's read/serialized --
    build_interaction_event must only be called once per logical event
    (interaction_service.create_interaction enforces this by construction)."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    first_read = event.interaction_id
    second_read = event.model_dump()["interaction_id"]
    third_read = event.model_dump_json()
    assert first_read == second_read
    assert first_read in third_read


def test_two_separate_build_calls_produce_different_ids():
    """Sanity check the inverse: two genuinely different logical events
    (two separate build_interaction_event calls) must NOT collide."""
    event_a = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    event_b = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    assert event_a.interaction_id != event_b.interaction_id


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def test_timestamp_generated_at_creation():
    before = datetime.utcnow()
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    after = datetime.utcnow()
    assert before <= event.timestamp <= after


def test_timestamp_naive_utc_matches_repo_convention():
    """This schema's universal convention (RefreshToken/User/Organization/
    UserSession/AuditEvent -- see Interaction model's own docstring for
    why) is naive datetime.utcnow(), not a timezone-aware value. tzinfo
    must be None, matching every other created_at column in this repo."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    assert event.timestamp.tzinfo is None


# ---------------------------------------------------------------------------
# Required / optional fields
# ---------------------------------------------------------------------------

def test_organization_id_required():
    with pytest.raises(ValidationError):
        InteractionEvent(service="rag", interaction_type="query")


def test_service_required():
    with pytest.raises(ValidationError):
        InteractionEvent(organization_id=1, interaction_type="query")


def test_interaction_type_required():
    with pytest.raises(ValidationError):
        InteractionEvent(organization_id=1, service="rag")


def test_optional_fields_default_to_none_or_empty():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
    )
    assert event.user_id is None
    assert event.session_id is None
    assert event.trace_id is None
    assert event.resource_type is None
    assert event.resource_id is None
    assert event.status is None
    assert event.decision is None
    assert event.metadata == {}


def test_all_fields_round_trip_through_persistence(db):
    event = interaction_service.build_interaction_event(
        organization_id=7,
        service="rag",
        interaction_type="query",
        action="search",
        user_id=42,
        session_id="11111111-2222-3333-4444-555555555555",
        trace_id="trace-abc",
        resource_type="publication",
        resource_id="pmid:123456",
        status="success",
        decision="allow",
        metadata={"workflow_id": "wf-1"},
    )
    interaction_service.persist_interaction(db, event)

    row = _row(event.interaction_id)
    assert row is not None
    assert row.organization_id == 7
    assert row.user_id == 42
    assert row.session_id == "11111111-2222-3333-4444-555555555555"
    assert row.trace_id == "trace-abc"
    assert row.service == "rag"
    assert row.interaction_type == "query"
    assert row.action == "search"
    assert row.resource_type == "publication"
    assert row.resource_id == "pmid:123456"
    assert row.status == "success"
    assert row.decision == "allow"
    assert row.event_metadata == {"workflow_id": "wf-1"}


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_persist_is_idempotent_on_duplicate_interaction_id(db):
    """event A, event A again -> one Interaction, not two."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )

    first = interaction_service.persist_interaction(db, event)
    second = interaction_service.persist_interaction(db, event)

    assert first is not None
    assert second is not None
    assert first.interaction_id == second.interaction_id

    db2 = _DirectSession()
    try:
        count = (
            db2.query(Interaction)
            .filter(Interaction.interaction_id == event.interaction_id)
            .count()
        )
    finally:
        db2.close()
    assert count == 1


def test_persist_duplicate_returns_the_original_row_unchanged(db):
    """A retried persist must not silently overwrite the original row's
    other fields with whatever the retry happened to carry."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="original-action",
    )
    interaction_service.persist_interaction(db, event)

    # Simulate a redelivered copy of the *same* logical event (same
    # interaction_id) -- persist_interaction must not create a second row
    # or mutate the first.
    db2 = _DirectSession()
    try:
        interaction_service.persist_interaction(db2, event)
    finally:
        db2.close()

    row = _row(event.interaction_id)
    assert row.action == "original-action"


# ---------------------------------------------------------------------------
# Organization isolation
# ---------------------------------------------------------------------------

def test_organization_scoped_query_excludes_other_orgs(db):
    org_a_event = interaction_service.build_interaction_event(
        organization_id=101, service="rag", interaction_type="query", action="a",
    )
    org_b_event = interaction_service.build_interaction_event(
        organization_id=202, service="rag", interaction_type="query", action="b",
    )
    interaction_service.persist_interaction(db, org_a_event)
    interaction_service.persist_interaction(db, org_b_event)

    db2 = _DirectSession()
    try:
        org_a_rows = db2.query(Interaction).filter(Interaction.organization_id == 101).all()
        org_a_ids = {row.interaction_id for row in org_a_rows}
    finally:
        db2.close()

    assert org_a_event.interaction_id in org_a_ids
    assert org_b_event.interaction_id not in org_a_ids


# ---------------------------------------------------------------------------
# Session correlation
# ---------------------------------------------------------------------------

def test_session_id_nullable_for_system_interaction(db):
    event = interaction_service.build_interaction_event(
        organization_id=1, service="workflow-bundles", interaction_type="system",
        action="scheduled_cleanup",
    )
    row = interaction_service.persist_interaction(db, event)
    assert row.session_id is None
    assert row.user_id is None


def test_session_id_populated_when_producer_supplies_it(db):
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
        user_id=5, session_id="66666666-7777-8888-9999-000000000000",
    )
    row = interaction_service.persist_interaction(db, event)
    assert row.session_id == "66666666-7777-8888-9999-000000000000"


def test_no_manufactured_session_for_system_events():
    """persist/build must never invent a session_id -- a system event
    with no session supplied stays NULL, not some synthetic placeholder."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="model-registry", interaction_type="system", action="register",
    )
    assert event.session_id is None


# ---------------------------------------------------------------------------
# Privacy / redaction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("forbidden_key", [
    "access_token", "refresh_token", "authorization", "cookie",
    "password", "api_key", "secret", "private_key", "Authorization",
    "ACCESS_TOKEN",
])
def test_metadata_strips_secret_shaped_keys(forbidden_key):
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
        metadata={forbidden_key: "should-never-be-stored", "workflow_id": "wf-1"},
    )
    assert forbidden_key not in event.metadata
    assert all(forbidden_key.lower() not in k.lower() for k in event.metadata)


def test_metadata_preserves_non_secret_context():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
        metadata={"workflow_id": "wf-1", "tool_name": "blast", "duration_ms": 1200},
    )
    assert event.metadata == {"workflow_id": "wf-1", "tool_name": "blast", "duration_ms": 1200}


def test_metadata_redaction_is_recursive():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
        metadata={"request": {"headers": {"authorization": "Bearer xyz"}, "path": "/v1/query"}},
    )
    assert "authorization" not in event.metadata["request"]["headers"]
    assert event.metadata["request"]["path"] == "/v1/query"


def test_metadata_redaction_never_raises_on_unexpected_shape():
    """_redact_metadata's own defensive except-branch: a metadata value
    that breaks iteration must not propagate -- fail open to an empty
    dict, same as every other failure path in this module, rather than
    blocking the Interaction entirely."""
    class _BrokenMapping(dict):
        def items(self):
            raise RuntimeError("simulated malformed metadata")

    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
        metadata=_BrokenMapping({"workflow_id": "wf-1"}),
    )
    assert event.metadata == {}


def test_persist_interaction_fails_open_on_non_integrity_db_error(db):
    """A genuine (non-duplicate) DB failure must not raise -- fail-open,
    matching audit_service.log_event's identical try/except/rollback/log
    shape. Returns None; the caller still has the event's interaction_id
    regardless (create_interaction's own contract)."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
    )
    broken_db = MagicMock()
    broken_db.commit.side_effect = RuntimeError("simulated connection loss")

    result = interaction_service.persist_interaction(broken_db, event)  # must not raise

    assert result is None
    broken_db.rollback.assert_called_once()


def test_persisted_row_never_contains_secret_shaped_values(db):
    """End-to-end: even if a producer's metadata carried a secret-shaped
    key, the persisted DB row must not contain it."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
        metadata={"access_token": "shhh", "refresh_token": "also-shhh"},
    )
    row = interaction_service.persist_interaction(db, event)
    serialized = str(row.event_metadata)
    assert "shhh" not in serialized
