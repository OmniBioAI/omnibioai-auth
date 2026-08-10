"""PR-B4 (Interaction Consumer/Persistence Worker): the Redis Streams
consumer-group -> `interactions` table pipeline that drains
`interactions:events` (published by PR-B2's own
interaction_service.publish_interaction, and by PR-B3's RAG producer)
into the durable table PR-B2 already created.

Deliberately a separate process/container from app/main.py's FastAPI app
(see Dockerfile.worker), not a background task started on FastAPI
startup -- mirrors omnibioai-security-audit's worker/main.py precedent
(PR4.2) exactly for the same reasons stated there: ingestion must survive
API restarts/deploys, the consumer workload scales independently of API
request volume, and API request latency must never depend on a Redis
Streams read happening on the ingestion side.

Not a blind copy of that precedent, though -- three deliberate
differences, each explained where it matters below:

1. Consumer identity is STABLE (INTERACTIONS_CONSUMER_NAME, a fixed
   default, not security-audit's `worker-{os.getpid()}`), so a restarted
   worker can reclaim its own crash-orphaned pending entries (see
   `_drain_own_pending` below) -- something a per-PID identity can never
   do, since a new process gets a new PID and therefore a permanently
   orphaned set of pending entries under the old, now-dead identity.
   This is the direct fix for the "delivered, persisted, worker died
   before XACK" scenario B4's own brief requires (Section 11): no
   XCLAIM/XAUTOCLAIM anywhere in this codebase (grepped -- neither repo
   uses them) is invented here since a single, stable-named consumer
   reading its own pending list (Redis Streams' ID `0`, not `>`) is
   sufficient for a single-replica deployment and needs no
   cross-consumer takeover protocol.

2. `handle_message` calls PR-B2's own `persist_interaction` directly,
   which never raises and already returns None only on genuine,
   non-duplicate failure (see that function's own docstring) -- so this
   worker's ack rule is simply "ack iff the return value is not None",
   not the try/except-around-Sink.write() shape security-audit's
   handle_message needs (that repo's Sink.write() propagates on
   failure).

3. Metadata redaction: PR-B2's own `build_interaction_event` is the only
   place interaction_service.py redacts secret-shaped metadata keys
   today, and only auth's own local call sites go through it. RAG's
   PR-B3 producer builds and XADDs a payload directly (ragbio/
   interactions.py's own build_interaction_event, a parallel, hand-kept-
   in-sync definition per that module's own docstring) and does not
   redact. Since this worker constructs its InteractionEvent straight
   from the wire (it must preserve the producer's own interaction_id/
   timestamp, so it cannot go back through build_interaction_event,
   whose default_factory fields would mint new ones), redaction would be
   silently skipped for every stream-sourced event unless this worker
   applies it itself -- so it explicitly reuses interaction_service's
   own `_redact_metadata`, the same one, rather than re-deriving a
   second copy of the forbidden-key-substrings list (exactly the
   drifted-second-implementation failure PR-B1 found and interaction_
   service.py's own module docstring says this design exists to avoid).
"""
import json
import logging
import os
import signal
from datetime import timezone

from pydantic import ValidationError
from redis import Redis
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.db.session import SessionLocal
from app.schemas.interaction import InteractionEvent
from app.services.interaction_service import STREAM, _redact_metadata, persist_interaction

logger = logging.getLogger("omnibioai.auth.workers.interaction_consumer")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
CONSUMER_GROUP = os.getenv("INTERACTIONS_CONSUMER_GROUP", "interaction-workers")
# Stable by default -- see module docstring point 1. Only override this if
# ever running more than one replica (each replica needs a distinct name,
# same as any Redis Streams consumer group).
CONSUMER_NAME = os.getenv("INTERACTIONS_CONSUMER_NAME", "interaction-worker")
READ_COUNT = int(os.getenv("INTERACTIONS_READ_COUNT", "10"))
READ_BLOCK_MS = int(os.getenv("INTERACTIONS_READ_BLOCK_MS", "5000"))


class InteractionStreamReader:
    """Thin wrapper over the redis-py Streams API this worker needs --
    mirrors omnibioai-security-audit's consumers/stream_reader.py::
    StreamReader shape (ensure_group/read_group/ack), plus
    `read_own_pending` for point 1 above, which that precedent has no
    equivalent of.
    """

    def __init__(self):
        self.redis = Redis.from_url(REDIS_URL, decode_responses=True)
        self.stream = STREAM

    def ensure_group(self, group=None):
        """Create the consumer group if it doesn't exist yet (idempotent).

        Starts at "0-0" (not "$"), matching security-audit's own
        ensure_group -- a brand-new group must also pick up any
        interactions:events entries already sitting in the stream before
        this worker's first run (including ones PR-B2's own
        publish_interaction has been emitting, unconsumed, since before
        B4 existed), not silently skip them.

        `group` defaults via `param or MODULE_CONSTANT` (resolved at call
        time), not a `def f(group=CONSUMER_GROUP)` default (bound once at
        class-definition/import time) -- matches security-audit's own
        AuditConfig-attribute-access idiom exactly, and, unlike an
        early-bound default, actually observes a runtime override of the
        module-level constant (relevant to this module's own test suite
        and to _drain_own_pending/run below, which all rely on that).
        """
        group = group or CONSUMER_GROUP
        try:
            self.redis.xgroup_create(self.stream, group, id="0-0", mkstream=True)
        except ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def read_own_pending(self, consumer=None, group=None, count=100, start="0"):
        """Reads from *this consumer's own* pending entries list (an
        explicit ID, not `>`) -- entries Redis already delivered to
        `consumer` under `group` that were never XACKed, with ID greater
        than `start`. Never blocks. See module docstring point 1: this is
        the crash-recovery path for "delivered -> persisted -> worker
        died before XACK", safe specifically because `consumer` is stable
        across restarts.

        `start` exists (rather than always passing "0") so
        `_drain_own_pending` can page forward past a message that stays
        unacked after being retried (e.g. a permanently malformed
        payload, Section 12) -- re-reading from "0" every time would
        return that same stuck entry forever and never terminate.
        """
        consumer = consumer or CONSUMER_NAME
        group = group or CONSUMER_GROUP
        result = self.redis.xreadgroup(group, consumer, {self.stream: start}, count=count)
        return result or []

    def read_new(self, consumer=None, group=None, count=None, block=None):
        """Reads undelivered ("new") messages for this consumer group."""
        consumer = consumer or CONSUMER_NAME
        group = group or CONSUMER_GROUP
        count = count if count is not None else READ_COUNT
        block = block if block is not None else READ_BLOCK_MS
        result = self.redis.xreadgroup(group, consumer, {self.stream: ">"}, count=count, block=block)
        return result or []

    def ack(self, message_id, group=None):
        group = group or CONSUMER_GROUP
        self.redis.xack(self.stream, group, message_id)


def _parse_event(raw_data: str) -> InteractionEvent:
    """Deserializes one `interactions:events` payload ({"data": <json>>}'s
    inner JSON string) into an InteractionEvent, tolerating the one known,
    benign shape difference between producers: PR-B3's RAG producer emits
    a timezone-aware ISO-8601 `timestamp` (datetime.now(timezone.utc).
    isoformat()), while PR-B2's own InteractionEvent/Interaction.created_at
    use this schema's universal naive-UTC convention (see that model's own
    docstring: "not a timezone-aware column, which would be the only one
    in the entire schema"). Pydantic parses either shape into a `datetime`
    without complaint, so this normalizes a tz-aware result to naive UTC
    before it ever reaches persist_interaction -- persist_interaction
    itself does no such normalization (it trusts its caller), and this is
    the one call site that hands it an event it did not build itself via
    build_interaction_event.

    Raises json.JSONDecodeError / pydantic.ValidationError on a malformed
    payload -- the caller (handle_message) decides what to do with that,
    mirroring parse_audit_event's identical contract in security-audit.
    """
    payload = json.loads(raw_data)
    event = InteractionEvent(**payload)
    if event.timestamp.tzinfo is not None:
        event = event.model_copy(
            update={"timestamp": event.timestamp.astimezone(timezone.utc).replace(tzinfo=None)}
        )
    # Module docstring point 3: redact secret-shaped metadata keys here,
    # the one place a stream-sourced event's metadata reaches persistence
    # without having already passed through build_interaction_event's own
    # redaction gate.
    if event.metadata:
        event = event.model_copy(update={"metadata": _redact_metadata(event.metadata)})
    return event


def handle_message(reader: InteractionStreamReader, message_id: str, fields: dict) -> bool:
    """Process one Redis Streams message. Returns True if it was acked.

    READ -> VALIDATE -> PERSIST DURABLY -> ACK, in that order, and only
    ack after persist_interaction returns a non-None row. Any failure
    along the way leaves the message unacknowledged in the consumer
    group's pending entries list, never dropped -- redelivered on the
    next `_drain_own_pending` after a restart, or immediately retried in
    the same process for a transient DB failure the caller loops back
    into (matching security-audit's own retry-by-redelivery model; no new
    in-process retry loop is introduced here).

    A malformed payload (bad JSON, or JSON that fails InteractionEvent
    validation) is logged and left unacked -- not crash-looped, not
    silently dropped, not routed to a dead-letter stream. No dead-letter
    or quarantine mechanism exists anywhere in this codebase today
    (grepped both this repo and omnibioai-security-audit); mirroring the
    only established convention for this exact situation
    (security-audit's own worker/main.py::handle_message, which leaves an
    unparseable audit event pending indefinitely rather than inventing a
    new production policy here) rather than building a new one
    unilaterally, per this PR's own Section 12.
    """
    try:
        event = _parse_event(fields["data"])
    except (KeyError, json.JSONDecodeError, ValidationError) as e:
        logger.warning(
            "interaction_consumer_parse_failed message_id=%s error=%s", message_id, e
        )
        return False

    db = SessionLocal()
    try:
        record = persist_interaction(db, event)
    finally:
        db.close()

    if record is None:
        # persist_interaction already logged+rolled back internally
        # (its own docstring: never raises, returns None only on a
        # genuine, non-duplicate failure). Do not ack -- redelivered on
        # the next own-pending drain or a future run.
        return False

    reader.ack(message_id)
    return True


def _drain_own_pending(reader: InteractionStreamReader) -> None:
    """Startup crash-recovery pass (module docstring point 1): pages
    forward through this consumer's own pending entries list exactly
    once, reprocessing each exactly like a live message. A message can be
    here because a prior run of this same, stably-named consumer read it,
    possibly even persisted it, and died before XACK -- persist_interaction
    is idempotent on interaction_id (PR-B2), so reprocessing (even a
    second successful persist attempt that hits the IntegrityError path)
    is always safe.

    The cursor advances to the last message_id seen in each page
    regardless of whether handle_message acked it, so a message that
    stays unacked after being retried (a permanently malformed payload,
    Section 12) does not stall this pass forever -- it is left pending
    (safe, inspectable via XPENDING) and the drain moves on.
    """
    start = "0"
    while True:
        response = reader.read_own_pending(start=start)
        messages_in_page = [
            (message_id, fields)
            for _stream_name, messages in response
            for message_id, fields in messages
        ]
        if not messages_in_page:
            return
        for message_id, fields in messages_in_page:
            handle_message(reader, message_id, fields)
        start = messages_in_page[-1][0]


_shutdown_requested = False


def _request_shutdown(signum, frame):  # pragma: no cover - exercised via run()'s flag directly
    global _shutdown_requested
    _shutdown_requested = True


def run(max_iterations=None):
    """Main consumer loop.

    max_iterations bounds the loop for tests; production (the __main__
    entrypoint below) leaves it None to run until SIGTERM/SIGINT.

    Graceful shutdown (Section 14): a SIGTERM/SIGINT sets a flag checked
    at the top of each iteration, so the loop exits between messages, not
    mid-message. In-flight safety does not actually depend on this,
    though -- handle_message only ever acks *after* persist_interaction's
    commit returns, so even an unceremonious kill mid-message leaves
    the message either fully persisted-and-unacked (safe: redelivered,
    idempotent no-op) or never persisted-and-unacked (safe: redelivered,
    persisted for the first time). The flag exists to stop starting new
    work promptly and shut down the Redis connection/DB engine cleanly,
    not to prevent corruption that can't happen here regardless.
    """
    global _shutdown_requested
    _shutdown_requested = False

    reader = InteractionStreamReader()
    reader.ensure_group()
    _drain_own_pending(reader)

    iterations = 0
    while not _shutdown_requested and (max_iterations is None or iterations < max_iterations):
        try:
            response = reader.read_new()
        except RedisTimeoutError:
            # Expected on an idle stream: read_new() blocks for up to
            # READ_BLOCK_MS and redis-py's own socket-level read timeout
            # can fire right at that boundary even though the server side
            # simply had nothing new to deliver -- functionally identical
            # to an empty response, not a failure. Same fix as
            # security-audit's PR-B0 follow-up (worker/main.py::run);
            # mirrored here deliberately since it is the exact same
            # redis-py behavior against the exact same blocking-read
            # pattern. No log here: normal idle-stream behavior.
            response = []
        except Exception as e:
            # A genuine unexpected Redis/connection failure. Print-and-
            # continue, matching handle_message()'s own convention: never
            # let a transient infra blip kill the whole worker process,
            # but keep it visible instead of silently swallowed.
            logger.warning("interaction_consumer_read_failed error=%s", e)
            response = []
        for _stream_name, messages in response:
            for message_id, fields in messages:
                handle_message(reader, message_id, fields)
        iterations += 1


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    # No logging is configured anywhere else in this process -- unlike
    # app/main.py's FastAPI process (which gets INFO-level output for
    # free from uvicorn's own logging setup when run via `uvicorn
    # app.main:app`), this worker is launched as a bare `python -m`
    # entrypoint (Dockerfile.worker's own CMD) with nothing upstream to
    # configure the root logger. Without this, Python's logging module
    # silently drops every logger.info() call (only WARNING+ reaches its
    # own "handler of last resort") -- confirmed by running the built
    # image standalone during this PR's own runtime validation: the
    # startup banner below never appeared in `docker logs` until this
    # line was added. security-audit's own worker/main.py sidesteps this
    # entirely by using print() instead of logging -- this worker keeps
    # using the logger (matching interaction_service.py's own module-wide
    # convention) and configures it explicitly instead.
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)
    logger.info(
        "interaction_consumer_starting group=%s consumer=%s stream=%s",
        CONSUMER_GROUP, CONSUMER_NAME, STREAM,
    )
    run()
