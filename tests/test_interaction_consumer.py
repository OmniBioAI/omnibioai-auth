"""PR-B4 regression tests: app/workers/interaction_consumer.py -- the
Redis Streams consumer-group loop that reads interactions:events, parses/
redacts/persists each message via PR-B2's own persist_interaction, and
only ACKs after a successful durable write.

Mirrors omnibioai-security-audit's tests/test_worker.py structure and
naming (PR4.2/PR-B0's own regression suite for the exact same class of
worker), fully mocked -- matching this repo's own established test
convention (tests/conftest.py mocks Redis/DB throughout, never spins up
real infrastructure for the pytest suite itself). Real-Redis/real-MySQL
proof lives in scripts/verify_interaction_consumer.py (this PR's own
integration validation script; see the PR-B4 report for why it is a
standalone script rather than a pytest-collected test -- neither
infrastructure is available in this repo's CI today).
"""
import json
import logging

import pytest
from unittest.mock import MagicMock, patch

import app.workers.interaction_consumer as consumer


def _raw(interaction_id="int-1", tz_aware=False, metadata=None, **overrides):
    payload = {
        "interaction_id": interaction_id,
        "timestamp": (
            "2026-01-01T12:00:00+00:00" if tz_aware else "2026-01-01T12:00:00"
        ),
        "organization_id": 1,
        "user_id": 2,
        "session_id": None,
        "trace_id": "trace-1",
        "service": "rag",
        "interaction_type": "query",
        "action": "rag.query",
        "resource_type": "study",
        "resource_id": "study-1",
        "status": "success",
        "decision": None,
        "metadata": metadata if metadata is not None else {},
    }
    payload.update(overrides)
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# _parse_event
# ---------------------------------------------------------------------------

def test_parse_event_valid():
    event = consumer._parse_event(_raw())
    assert event.interaction_id == "int-1"
    assert event.organization_id == 1
    assert event.service == "rag"


def test_parse_event_malformed_json_raises():
    with pytest.raises(json.JSONDecodeError):
        consumer._parse_event("not-json")


def test_parse_event_missing_required_field_raises():
    # organization_id/service/interaction_type are required, non-default
    # InteractionEvent fields.
    with pytest.raises(Exception):
        consumer._parse_event(json.dumps({"interaction_id": "x"}))


def test_parse_event_normalizes_tz_aware_timestamp_to_naive_utc():
    """PR-B3's RAG producer emits a tz-aware ISO timestamp; PR-B2's own
    Interaction.created_at is naive-UTC-only (see that model's own
    docstring). The consumer must normalize, not pass a tz-aware value
    through to persist_interaction."""
    event = consumer._parse_event(_raw(tz_aware=True))
    assert event.timestamp.tzinfo is None


def test_parse_event_naive_timestamp_passes_through_unchanged():
    event = consumer._parse_event(_raw(tz_aware=False))
    assert event.timestamp.tzinfo is None
    assert event.timestamp.isoformat() == "2026-01-01T12:00:00"


def test_parse_event_redacts_secret_shaped_metadata():
    """PR-B3's RAG producer does not redact before XADD (only PR-B2's own
    build_interaction_event does, and this worker cannot go back through
    that function -- see module docstring point 3). The consumer must
    apply the same redaction PR-B2 already established, not silently
    skip it for stream-sourced events."""
    event = consumer._parse_event(
        _raw(metadata={"token": "shhh", "authorization": "Bearer x", "mode": "rag"})
    )
    assert "token" not in event.metadata
    assert "authorization" not in event.metadata
    assert event.metadata["mode"] == "rag"


def test_parse_event_empty_metadata_stays_empty():
    event = consumer._parse_event(_raw(metadata={}))
    assert event.metadata == {}


# ---------------------------------------------------------------------------
# handle_message
# ---------------------------------------------------------------------------

def test_handle_message_persists_and_acks():
    reader = MagicMock()
    fake_record = MagicMock()

    with patch("app.workers.interaction_consumer.SessionLocal") as mock_session_local, \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=fake_record) as mock_persist:
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        result = consumer.handle_message(reader, "1-0", {"data": _raw()})

    assert result is True
    mock_persist.assert_called_once()
    reader.ack.assert_called_once_with("1-0")
    mock_db.close.assert_called_once()


def test_handle_message_passes_parsed_event_to_persist_interaction():
    reader = MagicMock()

    with patch("app.workers.interaction_consumer.SessionLocal"), \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=MagicMock()) as mock_persist:
        consumer.handle_message(reader, "1-0", {"data": _raw(interaction_id="evt-full")})

    passed_event = mock_persist.call_args[0][1]
    assert passed_event.interaction_id == "evt-full"
    assert passed_event.service == "rag"


def test_handle_message_does_not_ack_on_parse_failure():
    reader = MagicMock()

    result = consumer.handle_message(reader, "1-0", {"data": "not-json"})

    assert result is False
    reader.ack.assert_not_called()


def test_handle_message_does_not_ack_on_missing_required_field():
    reader = MagicMock()

    result = consumer.handle_message(
        reader, "1-0", {"data": json.dumps({"interaction_id": "x"})}
    )

    assert result is False
    reader.ack.assert_not_called()


def test_handle_message_does_not_ack_on_persist_failure():
    """persist_interaction returns None (never raises) on a genuine,
    non-duplicate failure -- READ -> VALIDATE -> PERSIST -> ACK means no
    ack when PERSIST did not durably succeed."""
    reader = MagicMock()

    with patch("app.workers.interaction_consumer.SessionLocal") as mock_session_local, \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=None):
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        result = consumer.handle_message(reader, "1-0", {"data": _raw()})

    assert result is False
    reader.ack.assert_not_called()
    # session is still closed even on failure
    mock_db.close.assert_called_once()


def test_handle_message_duplicate_interaction_id_still_acks():
    """persist_interaction's own idempotency (IntegrityError -> return
    the pre-existing row, PR-B2) means a redelivered duplicate is a safe
    ack, not a failure to retry."""
    reader = MagicMock()
    existing_record = MagicMock()

    with patch("app.workers.interaction_consumer.SessionLocal"), \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=existing_record):
        result = consumer.handle_message(reader, "2-0", {"data": _raw(interaction_id="dup-1")})

    assert result is True
    reader.ack.assert_called_once_with("2-0")


def test_handle_message_retry_after_failure_then_succeeds():
    """Simulates a worker restart/retry: the same (unacked) message is
    handled again and this time persistence succeeds -- it must now ack."""
    reader = MagicMock()

    with patch("app.workers.interaction_consumer.SessionLocal"), \
         patch(
             "app.workers.interaction_consumer.persist_interaction",
             side_effect=[None, MagicMock()],
         ):
        first = consumer.handle_message(reader, "1-0", {"data": _raw()})
        second = consumer.handle_message(reader, "1-0", {"data": _raw()})

    assert first is False
    assert second is True
    reader.ack.assert_called_once_with("1-0")


def test_handle_message_closes_db_session_even_on_parse_failure_path():
    """Parse failure returns before SessionLocal() is ever called -- no
    session to leak."""
    reader = MagicMock()
    with patch("app.workers.interaction_consumer.SessionLocal") as mock_session_local:
        consumer.handle_message(reader, "1-0", {"data": "not-json"})
    mock_session_local.assert_not_called()


# ---------------------------------------------------------------------------
# run() -- consumer-group startup + loop
# ---------------------------------------------------------------------------

def _reader(pending=None, new=None):
    mock_reader = MagicMock()
    mock_reader.read_own_pending.return_value = pending or []
    mock_reader.read_new.return_value = new or []
    return mock_reader


def test_run_creates_consumer_group_on_startup():
    mock_reader = _reader()
    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=1)
    mock_reader.ensure_group.assert_called_once()


def test_run_drains_own_pending_before_reading_new():
    """Module docstring point 1: a message left in this consumer's own
    PEL from a prior crashed run must be reprocessed on startup, before
    any new stream reads."""
    mock_reader = MagicMock()
    mock_reader.read_own_pending.side_effect = [
        [(consumer.STREAM, [("1-0", {"data": _raw(interaction_id="pending-1")})])],
        [],
    ]
    mock_reader.read_new.return_value = []

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader), \
         patch("app.workers.interaction_consumer.handle_message") as mock_handle:
        consumer.run(max_iterations=1)

    mock_handle.assert_called_once_with(
        mock_reader, "1-0", {"data": _raw(interaction_id="pending-1")}
    )


def test_run_own_pending_drain_pages_forward_past_stuck_message():
    """A message that stays unacked even after retry (e.g. permanently
    malformed) must not stall the drain forever -- the cursor advances
    past it using the last-seen message_id, matching Redis Streams'
    history-read pagination semantics."""
    mock_reader = MagicMock()
    mock_reader.read_own_pending.side_effect = [
        [(consumer.STREAM, [("1-0", {"data": "not-json"})])],
        [],
    ]
    mock_reader.read_new.return_value = []

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=1)  # must terminate, not hang

    assert mock_reader.read_own_pending.call_count == 2
    first_call_kwargs = mock_reader.read_own_pending.call_args_list[0].kwargs
    second_call_kwargs = mock_reader.read_own_pending.call_args_list[1].kwargs
    assert first_call_kwargs.get("start", "0") == "0"
    assert second_call_kwargs.get("start") == "1-0"


def test_run_processes_messages_from_read_new():
    mock_reader = _reader(
        new=[(consumer.STREAM, [("1-0", {"data": _raw(interaction_id="evt-a")})])]
    )
    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader), \
         patch("app.workers.interaction_consumer.handle_message") as mock_handle:
        consumer.run(max_iterations=1)
    mock_handle.assert_called_once_with(
        mock_reader, "1-0", {"data": _raw(interaction_id="evt-a")}
    )


def test_run_stops_after_max_iterations():
    mock_reader = _reader()
    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=3)
    assert mock_reader.read_new.call_count == 3


# ---------------------------------------------------------------------------
# run() -- Redis timeout/idle + unexpected-exception handling
#
# Regression coverage for the exact PR-B0/security-audit crash-loop class
# of bug this PR's own brief calls out (Section 13): read_new() blocks up
# to READ_BLOCK_MS, and redis-py's own socket-level read timeout can fire
# right at that boundary on an idle stream -- expected, not a failure.
# ---------------------------------------------------------------------------

def test_run_continues_after_read_timeout():
    from redis.exceptions import TimeoutError as RedisTimeoutError

    mock_reader = _reader()
    mock_reader.read_new.side_effect = RedisTimeoutError("Timeout reading from socket")

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=3)  # must not raise

    assert mock_reader.read_new.call_count == 3


def test_run_processes_a_message_after_a_timeout():
    from redis.exceptions import TimeoutError as RedisTimeoutError

    mock_reader = _reader()
    mock_reader.read_new.side_effect = [
        RedisTimeoutError("Timeout reading from socket"),
        [(consumer.STREAM, [("1-0", {"data": _raw(interaction_id="after-timeout")})])],
    ]

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader), \
         patch("app.workers.interaction_consumer.handle_message") as mock_handle:
        consumer.run(max_iterations=2)

    mock_handle.assert_called_once_with(
        mock_reader, "1-0", {"data": _raw(interaction_id="after-timeout")}
    )


def test_run_logs_but_survives_unexpected_read_exception(caplog):
    from redis.exceptions import ConnectionError as RedisConnectionError

    mock_reader = _reader()
    mock_reader.read_new.side_effect = [
        RedisConnectionError("connection reset by peer"),
        [],
    ]

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        with caplog.at_level(logging.WARNING, logger="omnibioai.auth.workers.interaction_consumer"):
            consumer.run(max_iterations=2)  # must not raise

    assert "connection reset by peer" in caplog.text


def test_run_does_not_swallow_keyboard_interrupt():
    mock_reader = _reader()
    mock_reader.read_new.side_effect = KeyboardInterrupt()

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        raised = False
        try:
            consumer.run(max_iterations=1)
        except KeyboardInterrupt:
            raised = True

    assert raised is True


# ---------------------------------------------------------------------------
# Consumer-group behavior: redelivery / duplicate delivery / worker restart
# ---------------------------------------------------------------------------

def test_redelivered_message_after_worker_restart_recovered_via_own_pending():
    """Simulates: message delivered to this stably-named consumer,
    worker crashes before ack, worker restarts (a fresh run() call, same
    consumer identity) -- the message must surface via read_own_pending
    on the new run, not be permanently lost."""
    mock_reader = MagicMock()
    mock_reader.read_own_pending.side_effect = [
        [(consumer.STREAM, [("1-0", {"data": _raw(interaction_id="crash-recover")})])],
        [],
    ]
    mock_reader.read_new.return_value = []

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader), \
         patch("app.workers.interaction_consumer.SessionLocal"), \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=MagicMock()) as mock_persist:
        consumer.run(max_iterations=1)

    mock_persist.assert_called_once()
    mock_reader.ack.assert_called_once_with("1-0")


def test_duplicate_delivery_across_two_runs_yields_one_persist_success_one_idempotent_noop():
    """Redis at-least-once delivery: the same interaction_id can be
    XREADGROUP-delivered twice (e.g. once live, once via own-pending
    redelivery after a crash between persist and ack). Both calls reach
    persist_interaction; PR-B2's own idempotency is what collapses them
    to one row -- this test only proves the worker calls persist_interaction
    (and acks) both times, not that it invents its own dedup."""
    mock_reader = _reader(
        new=[(consumer.STREAM, [("1-0", {"data": _raw(interaction_id="dup-evt")})])]
    )

    with patch("app.workers.interaction_consumer.SessionLocal"), \
         patch("app.workers.interaction_consumer.persist_interaction", return_value=MagicMock()) as mock_persist, \
         patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=1)
        consumer.run(max_iterations=1)

    assert mock_persist.call_count == 2
    assert mock_reader.ack.call_count == 2


# ---------------------------------------------------------------------------
# Graceful shutdown (Section 14)
# ---------------------------------------------------------------------------

def test_run_stops_on_shutdown_flag_between_iterations():
    mock_reader = _reader()
    call_count = {"n": 0}

    def _read_new(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:
            consumer._shutdown_requested = True
        return []

    mock_reader.read_new.side_effect = _read_new

    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run()  # no max_iterations -- must rely on the shutdown flag to terminate

    assert call_count["n"] == 2


def test_sigterm_handler_sets_shutdown_flag():
    consumer._shutdown_requested = False
    try:
        consumer._request_shutdown(15, None)
        assert consumer._shutdown_requested is True
    finally:
        consumer._shutdown_requested = False


def test_run_resets_shutdown_flag_on_fresh_start():
    """A previous run() that exited via shutdown must not leave the next
    run() (e.g. after a supervisor restart within the same process --
    not the normal deployment shape, but must not be a latent trap)
    exiting immediately on iteration 1."""
    consumer._shutdown_requested = True
    mock_reader = _reader()
    with patch("app.workers.interaction_consumer.InteractionStreamReader", return_value=mock_reader):
        consumer.run(max_iterations=2)
    assert mock_reader.read_new.call_count == 2
