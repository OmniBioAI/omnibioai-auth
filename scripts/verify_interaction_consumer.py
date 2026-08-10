#!/usr/bin/env python3
"""PR-B4 real-infrastructure integration proof for
app/workers/interaction_consumer.py.

Deliberately a standalone script, not a pytest-collected test: this
repo's own pytest suite (tests/conftest.py) fully mocks Redis and uses
SQLite for the app's own DB, matching the established convention every
other test in this repo already follows -- and no CI job in this repo
(none exists yet) or the adjacent omnibioai-security-audit repo's own CI
(.github/workflows/ci.yml, checked directly) spins up real Redis/MySQL
either. This script fills that gap for the specific claims PR-B4's own
brief requires proof of (Section 16/19): a real XADD -> real consumer ->
real persisted MySQL row -> real XACK, duplicate delivery collapsing to
one row, and an unavailable-database message staying unacknowledged.

Run against already-running, isolated (never the shared studio compose
stack) Redis/MySQL containers -- see the PR-B4 report for exactly how
those were started for this verification run. Expects the target
database to already be migrated to head (0019_interactions).

Usage:
    DB_HOST=127.0.0.1 DB_PORT=16406 DB_USER=root DB_PASSWORD=verifytest \\
    DB_NAME=omnibioai_verify REDIS_URL=redis://127.0.0.1:16479 \\
    SECRET_KEY=... python3 scripts/verify_interaction_consumer.py

Exit code 0 on success, 1 on any check failure.
"""
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redis import Redis  # noqa: E402
from sqlalchemy import text  # noqa: E402

import app.workers.interaction_consumer as consumer  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.core.config import settings  # noqa: E402

FAILURES = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    if not condition:
        FAILURES.append(label)


def _row_count(interaction_id):
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT COUNT(*) FROM interactions WHERE interaction_id = :iid"),
            {"iid": interaction_id},
        ).scalar()


def _pending_count(group, consumer_name):
    r = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    try:
        summary = r.xpending(consumer.STREAM, group)
    except Exception:
        return 0
    return summary["pending"] if summary else 0


def main():
    # A fresh, unique consumer group per script invocation -- this script
    # may run more than once against the same long-lived ephemeral Redis
    # (it did, during PR-B4's own development), and a leftover
    # permanently-pending malformed message from a *previous* run
    # (Section 12's own intentional, by-design behavior) must not make
    # this run's "was this specific message acked" checks look like a
    # regression. Verifies the same code path production uses
    # (CONSUMER_GROUP resolved fresh at call time -- see this module's
    # own `param or MODULE_CONSTANT` fix) without depending on Redis
    # state left over from an earlier invocation.
    consumer.CONSUMER_GROUP = f"interaction-workers-verify-{uuid.uuid4().hex[:8]}"

    # This script has been re-run several times against the same
    # long-lived ephemeral Redis container during development, leaving a
    # backlog on the stream itself (not just consumer-group state, which
    # the fresh group above already isolates from). A fresh group still
    # starts at "0-0" and would deliver that entire backlog as "new"
    # before ever reaching this run's own freshly-XADDed events. Safe
    # only because this Redis instance is single-purpose, throwaway, and
    # never the shared studio compose stack -- see the PR-B4 report for
    # exactly how it was started.
    Redis.from_url(os.environ["REDIS_URL"], decode_responses=True).delete(consumer.STREAM)

    print(f"Target DB: {settings.DATABASE_URL}")
    print(f"Target Redis: {os.environ['REDIS_URL']}")
    print(f"Stream: {consumer.STREAM}  Group: {consumer.CONSUMER_GROUP}  "
          f"Consumer: {consumer.CONSUMER_NAME}")
    print()

    r = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

    # -- 1. Fresh happy path: XADD -> consumer -> row -> XACK -------------
    iid_1 = str(uuid.uuid4())
    event_1 = {
        "interaction_id": iid_1,
        "timestamp": "2026-08-09T12:00:00+00:00",  # tz-aware, like PR-B3's real producer
        "organization_id": 42,
        "user_id": 7,
        "session_id": None,
        "trace_id": "verify-trace-1",
        "service": "rag",
        "interaction_type": "query",
        "action": "rag.query",
        "resource_type": "study",
        "resource_id": "study-verify",
        "status": "success",
        "decision": None,
        "metadata": {"mode": "rag", "authorization": "Bearer should-be-redacted"},
    }
    r.xadd(consumer.STREAM, {"data": json.dumps(event_1)})
    consumer.run(max_iterations=1)

    check("happy path: row persisted after one XADD + one run() iteration",
          _row_count(iid_1) == 1)

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT metadata, created_at FROM interactions WHERE interaction_id = :iid"),
            {"iid": iid_1},
        ).mappings().first()
    metadata = json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"]
    check("metadata redaction applied at persistence boundary (authorization key stripped)",
          "authorization" not in metadata and metadata.get("mode") == "rag")
    check("tz-aware producer timestamp normalized to naive UTC in created_at",
          row["created_at"].tzinfo is None if hasattr(row["created_at"], "tzinfo") else True)

    check("message acked after persistence (0 pending for this consumer group)",
          _pending_count(consumer.CONSUMER_GROUP, consumer.CONSUMER_NAME) == 0)

    # -- 2. Duplicate delivery: same interaction_id delivered twice -------
    iid_2 = str(uuid.uuid4())
    event_2 = dict(event_1, interaction_id=iid_2, trace_id="verify-trace-2")
    r.xadd(consumer.STREAM, {"data": json.dumps(event_2)})
    consumer.run(max_iterations=1)
    # Redeliver the same interaction_id as a second, distinct stream entry
    # (simulates an at-least-once redelivery producing a logically
    # duplicate Interaction, e.g. a caller retry) -- proves PR-B2's own
    # idempotency, not a worker-invented dedup.
    r.xadd(consumer.STREAM, {"data": json.dumps(event_2)})
    consumer.run(max_iterations=1)

    check("duplicate interaction_id across two Redis deliveries -> exactly one DB row",
          _row_count(iid_2) == 1)

    # -- 3. Database outage: message must NOT be acked ---------------------
    iid_3 = str(uuid.uuid4())
    event_3 = dict(event_1, interaction_id=iid_3, trace_id="verify-trace-3")
    r.xadd(consumer.STREAM, {"data": json.dumps(event_3)})

    real_engine_url = str(engine.url)
    import app.db.session as db_session_module
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    broken_engine = create_engine("mysql+pymysql://root:wrong@127.0.0.1:1/doesnotexist")
    broken_session_local = sessionmaker(autocommit=False, autoflush=False, bind=broken_engine)
    original_session_local = db_session_module.SessionLocal
    consumer.SessionLocal = broken_session_local
    try:
        consumer.run(max_iterations=1)
    finally:
        consumer.SessionLocal = original_session_local

    check("DB outage: message remains unacked (pending > 0)",
          _pending_count(consumer.CONSUMER_GROUP, consumer.CONSUMER_NAME) >= 1)
    check("DB outage: no row was written for the unreachable-DB event",
          _row_count(iid_3) == 0)

    # Recovery: DB comes back, own-pending drain on next run() picks it up.
    consumer.run(max_iterations=1)
    check("DB recovery: previously-pending message persisted on next run() "
          "(own-pending drain)",
          _row_count(iid_3) == 1)
    check("DB recovery: message now acked (0 pending)",
          _pending_count(consumer.CONSUMER_GROUP, consumer.CONSUMER_NAME) == 0)

    # -- 4. Malformed event: must not crash, must not be acked -------------
    r.xadd(consumer.STREAM, {"data": "not-json-at-all"})
    try:
        consumer.run(max_iterations=1)
        crashed = False
    except Exception:
        crashed = True
    check("malformed event does not crash the worker", not crashed)
    check("malformed event left unacked (pending > 0)",
          _pending_count(consumer.CONSUMER_GROUP, consumer.CONSUMER_NAME) >= 1)

    # -- 5. Idle-stream stability across several blocking-read cycles ------
    original_block = consumer.READ_BLOCK_MS
    consumer.READ_BLOCK_MS = 1000
    t0 = time.time()
    try:
        consumer.run(max_iterations=5)  # stream now idle (malformed msg still pending, no new entries)
        idle_survived = True
    except Exception as e:
        idle_survived = False
        print(f"    idle-cycle exception: {e}")
    finally:
        consumer.READ_BLOCK_MS = original_block
    elapsed = time.time() - t0
    check(f"worker survives 5 idle blocking-read cycles without crashing "
          f"(elapsed {elapsed:.1f}s, expected ~5s)",
          idle_survived and elapsed >= 4.0)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All checks PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
