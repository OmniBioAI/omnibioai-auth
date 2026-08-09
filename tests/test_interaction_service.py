"""PR-B2 (Interactions Foundation): app/services/interaction_service.py's
Redis publishing contract.

Mocked tests below never touch a real Redis instance. The real-backend
tests at the bottom (mirroring omnibioai-security-audit's
tests/test_worker_integration_real_backends.py pattern) run only when a
real Redis is reachable -- skipped, not failed, in CI or any environment
without one. They use their own isolated stream name, never
`interactions:events` itself, and are cleaned up (XDEL) after.
"""
import json
import os
import uuid
from unittest.mock import MagicMock, patch

import pytest
import redis as redis_lib

from app.schemas.interaction import InteractionEvent
from app.services import interaction_service


# ---------------------------------------------------------------------------
# publish_interaction -- mocked, fail-open behavior
# ---------------------------------------------------------------------------

def test_publish_interaction_calls_xadd_with_correct_stream():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
    )
    with patch.object(interaction_service, "_redis") as mock_redis:
        interaction_service.publish_interaction(event)

    mock_redis.xadd.assert_called_once()
    call_args = mock_redis.xadd.call_args
    assert call_args[0][0] == "interactions:events"


def test_publish_interaction_payload_is_the_event_json():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="search",
        trace_id="trace-xyz",
    )
    with patch.object(interaction_service, "_redis") as mock_redis:
        interaction_service.publish_interaction(event)

    fields = mock_redis.xadd.call_args[0][1]
    payload = json.loads(fields["data"])
    assert payload["interaction_id"] == event.interaction_id
    assert payload["trace_id"] == "trace-xyz"
    assert payload["organization_id"] == 1


def test_publish_interaction_never_raises_when_redis_unavailable():
    """Fail-open: a Redis outage must not propagate to the caller."""
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
    )
    with patch.object(interaction_service, "_redis") as mock_redis:
        mock_redis.xadd.side_effect = redis_lib.exceptions.ConnectionError("down")
        interaction_service.publish_interaction(event)  # must not raise


def test_publish_interaction_never_raises_on_generic_exception():
    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query",
    )
    with patch.object(interaction_service, "_redis") as mock_redis:
        mock_redis.xadd.side_effect = Exception("unexpected")
        interaction_service.publish_interaction(event)  # must not raise


# ---------------------------------------------------------------------------
# create_interaction -- build + persist + publish, using the direct-DB
# session pattern established in test_interaction_foundation.py
# ---------------------------------------------------------------------------

def test_create_interaction_persists_and_publishes():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite:///./test.db")
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        with patch.object(interaction_service, "_redis") as mock_redis:
            event = interaction_service.create_interaction(
                db, organization_id=1, service="rag", interaction_type="query", action="search",
            )
        mock_redis.xadd.assert_called_once()
        assert event.interaction_id

        from app.db.models import Interaction
        row = db.query(Interaction).filter(Interaction.interaction_id == event.interaction_id).first()
        assert row is not None
    finally:
        db.close()


def test_create_interaction_returns_event_even_if_redis_fails():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite:///./test.db")
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        with patch.object(interaction_service, "_redis") as mock_redis:
            mock_redis.xadd.side_effect = Exception("redis down")
            event = interaction_service.create_interaction(
                db, organization_id=1, service="rag", interaction_type="query",
            )
        assert event.interaction_id  # caller still has a stable identity

        from app.db.models import Interaction
        row = db.query(Interaction).filter(Interaction.interaction_id == event.interaction_id).first()
        assert row is not None  # DB persistence unaffected by Redis failure
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Real Redis integration -- skipped (not failed) when unreachable
# ---------------------------------------------------------------------------

TEST_REDIS_URL = os.getenv("B2_TEST_REDIS_URL", "redis://localhost:6380")
TEST_STREAM = f"interactions:events:b2-test-{uuid.uuid4().hex[:8]}"


def _real_redis_available() -> bool:
    try:
        r = redis_lib.from_url(TEST_REDIS_URL, socket_connect_timeout=2)
        r.ping()
        return True
    except Exception:
        return False


pytestmark_real = pytest.mark.skipif(
    not _real_redis_available(),
    reason="real Redis not reachable (set B2_TEST_REDIS_URL, or run against "
    "the dev docker-compose stack) -- skipped, not failed",
)


@pytestmark_real
def test_real_publish_preserves_all_fields():
    """publish Interaction -> real Redis Stream -> read event -> every
    field preserved (interaction_id, timestamp, organization_id,
    session_id, trace_id, metadata)."""
    event = interaction_service.build_interaction_event(
        organization_id=99,
        service="rag",
        interaction_type="query",
        action="search",
        user_id=7,
        session_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        trace_id="b2-real-trace-1",
        metadata={"workflow_id": "wf-real-1"},
    )

    real_redis = redis_lib.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        with patch.object(interaction_service, "STREAM", TEST_STREAM), \
             patch.object(interaction_service, "_redis", real_redis):
            interaction_service.publish_interaction(event)

        entries = real_redis.xrange(TEST_STREAM)
        assert len(entries) == 1
        _message_id, fields = entries[0]
        payload = json.loads(fields["data"])

        assert payload["interaction_id"] == event.interaction_id
        assert payload["organization_id"] == 99
        assert payload["user_id"] == 7
        assert payload["session_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        assert payload["trace_id"] == "b2-real-trace-1"
        assert payload["metadata"] == {"workflow_id": "wf-real-1"}
    finally:
        real_redis.delete(TEST_STREAM)


@pytestmark_real
def test_real_duplicate_delivery_still_yields_one_persisted_interaction():
    """The full contract: build one event, publish it twice (simulating
    redelivery of the same logical event), read both raw stream entries
    back, then persist each parsed copy -- exactly one Interaction row
    must result, proving Redis-level duplication and DB-level idempotency
    compose correctly end to end."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models import Interaction

    event = interaction_service.build_interaction_event(
        organization_id=1, service="rag", interaction_type="query", action="dup-check",
    )

    real_redis = redis_lib.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        with patch.object(interaction_service, "STREAM", TEST_STREAM), \
             patch.object(interaction_service, "_redis", real_redis):
            interaction_service.publish_interaction(event)  # first delivery
            interaction_service.publish_interaction(event)  # simulated redelivery

        entries = real_redis.xrange(TEST_STREAM)
        assert len(entries) == 2  # Redis itself does not dedupe -- expected

        engine = create_engine("sqlite:///./test.db")
        Session = sessionmaker(bind=engine)

        for _message_id, fields in entries:
            payload = json.loads(fields["data"])
            parsed_event = InteractionEvent(**payload)
            db = Session()
            try:
                interaction_service.persist_interaction(db, parsed_event)
            finally:
                db.close()

        db = Session()
        try:
            count = (
                db.query(Interaction)
                .filter(Interaction.interaction_id == event.interaction_id)
                .count()
            )
        finally:
            db.close()
        assert count == 1  # DB-level idempotency held despite 2 stream entries
    finally:
        real_redis.delete(TEST_STREAM)
