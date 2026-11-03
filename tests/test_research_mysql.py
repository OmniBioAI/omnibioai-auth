"""Real MySQL/Redis tests requiring explicit disposable loopback ports."""
import importlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier

import pytest
import redis
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.config import settings
from app.core import rate_limit
from app.api import routes_research_inquiries as routes
from app.db.research_inquiry import ResearchInquiry
from app.schemas.research_inquiry import ResearchInquiryCreate
from app.services import research_inquiry_service as service
from tests.test_research_inquiries import payload

HEAD = "0041_validate_inquiry_schema"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def database(monkeypatch):
    host = os.environ.get("RESEARCH_TEST_MYSQL_HOST", "127.0.0.1")
    port = os.environ.get("RESEARCH_TEST_MYSQL_PORT", "")
    assert port.isdigit(), "Set RESEARCH_TEST_MYSQL_PORT to a disposable MySQL container"
    name = "ri_qual_" + uuid.uuid4().hex[:12]
    admin = create_engine(f"mysql+pymysql://root@{host}:{port}/mysql")
    with admin.begin() as connection:
        connection.execute(text(f"CREATE DATABASE {name} CHARACTER SET utf8mb4"))
    admin.dispose()
    engine = create_engine(f"mysql+pymysql://root@{host}:{port}/{name}")
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_HMAC_KEY", "synthetic-test-only-key-at-least-32-bytes")
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_TO", "")
    yield engine, cfg
    engine.dispose()  # Container removal is the explicit test-data cleanup boundary.


def migrate(database, target=HEAD):
    engine, cfg = database
    command.upgrade(cfg, target)
    return engine, cfg


def test_revision_graph_is_single_complete_chain():
    script = ScriptDirectory(str(ROOT / "alembic"))
    revisions = list(reversed(list(script.walk_revisions())))
    assert script.get_heads() == [HEAD] and len(revisions) == 41
    assert len({r.revision for r in revisions}) == 41
    assert revisions[0].down_revision is None
    assert all(r.down_revision == p.revision for p, r in zip(revisions, revisions[1:]))
    assert [r.revision for r in revisions[-5:]] == [
        "0037_license_generation_idem", "0038_encrypt_license_replay",
        "0039_version_license_key_peppers", "0040_research_inquiries", HEAD]


def test_clean_mysql_upgrade_and_schema_model_parity(database):
    engine, cfg = migrate(database)
    command.upgrade(cfg, HEAD)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == HEAD
        assert connection.execute(text("SELECT VERSION()")).scalar_one().startswith("8.0.")
    inspector = inspect(engine)
    actual = {c["name"]: c for c in inspector.get_columns("research_inquiries")}
    expected = ResearchInquiry.__table__
    assert set(actual) == set(expected.c.keys())
    for column in expected.c:
        reflected = actual[column.name]
        assert reflected["type"]._type_affinity is column.type._type_affinity
        assert getattr(reflected["type"], "length", None) == getattr(column.type, "length", None)
        assert reflected["nullable"] == column.nullable
        assert (str(reflected["default"]).strip("'()") if reflected["default"] is not None else None) == (
            str(column.server_default.arg) if column.server_default is not None else None)
    assert inspector.get_pk_constraint(expected.name)["constrained_columns"] == ["inquiry_id"]
    assert inspector.get_foreign_keys(expected.name) == []
    assert {tuple(c["column_names"]) for c in inspector.get_unique_constraints(expected.name)} == {("duplicate_fingerprint",)}
    indexes = {c["name"]: c for c in inspector.get_indexes(expected.name) if not c["unique"]}
    assert set(indexes) == {index.name for index in expected.indexes}
    for index in expected.indexes:
        assert indexes[index.name]["column_names"] == [c.name for c in index.columns]
    assert len(inspector.get_check_constraints(expected.name)) == 2


def test_existing_revision_0036_rows_survive_each_upgrade(database):
    engine, cfg = migrate(database, "0036_mfa_enrollment_sessions")
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO license_keys (email,plan,key_digest) VALUES (:email,'beta',:digest)"),
                           {"email": "synthetic@example.edu", "digest": "a" * 64})
    for revision in ["0037_license_generation_idem", "0038_encrypt_license_replay",
                     "0039_version_license_key_peppers", "0040_research_inquiries", HEAD]:
        command.upgrade(cfg, revision)
    with engine.connect() as connection:
        row = connection.execute(text("SELECT key_digest,email,plan,key_pepper_id FROM license_keys")).one()
        assert tuple(row) == ("a" * 64, "synthetic@example.edu", "beta", None)
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == HEAD


def test_empty_downgrade_and_reupgrade(database):
    engine, cfg = migrate(database)
    command.downgrade(cfg, "0039_version_license_key_peppers")
    assert not inspect(engine).has_table("research_inquiries")
    command.upgrade(cfg, HEAD)
    assert inspect(engine).has_table("research_inquiries")


def test_populated_downgrade_refused_and_data_retained(database):
    engine, cfg = migrate(database)
    with Session(engine) as db:
        inquiry_id = service.create(db, ResearchInquiryCreate.model_validate(payload())).inquiry_id
    with pytest.raises(RuntimeError, match="populated"):
        command.downgrade(cfg, "0039_version_license_key_peppers")
    with Session(engine) as db:
        assert db.get(ResearchInquiry, inquiry_id).institution == "Example University"
    command.upgrade(cfg, HEAD)


def test_forward_guard_repairs_interrupted_index_creation(database):
    engine, cfg = migrate(database, "0040_research_inquiries")
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_research_inquiry_processing ON research_inquiries"))
    command.upgrade(cfg, HEAD)
    assert "ix_research_inquiry_processing" in {i["name"] for i in inspect(engine).get_indexes("research_inquiries")}


def test_forward_guard_refuses_incompatible_preexisting_type(database):
    engine, cfg = migrate(database, "0040_research_inquiries")
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE research_inquiries MODIFY full_name VARCHAR(10) NOT NULL"))
    with pytest.raises(RuntimeError, match="Incompatible research_inquiries.full_name"):
        command.upgrade(cfg, HEAD)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0040_research_inquiries"


def test_mysql_constraints_and_rollback(database):
    engine, _ = migrate(database)
    with Session(engine) as db:
        row = service.create(db, ResearchInquiryCreate.model_validate(payload()))
        inquiry_id = row.inquiry_id
        for field, expected in [("processing_status", "new"), ("notification_status", "pending")]:
            setattr(row, field, "unsupported")
            with pytest.raises(OperationalError) as failure:
                db.commit()
            assert failure.value.orig.args[0] == 3819
            db.rollback()
            assert getattr(db.get(ResearchInquiry, inquiry_id), field) == expected


def test_mysql_concurrent_duplicates(database):
    engine, _ = migrate(database)
    barrier = Barrier(2)
    def submit():
        with Session(engine) as db:
            barrier.wait(timeout=10)
            try:
                return service.create(db, ResearchInquiryCreate.model_validate(payload())).inquiry_id
            except service.DuplicateInquiry:
                return "duplicate"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: submit(), range(2)))
    assert results.count("duplicate") == 1
    with Session(engine) as db:
        assert db.query(ResearchInquiry).count() == 1
        assert db.query(ResearchInquiry).one().inquiry_id in results


def test_mysql_serial_notification_retries(database, monkeypatch):
    engine, _ = migrate(database)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_TO", "authorized@example.org")
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_IDEMPOTENCY_CONFIRMED", True)
    calls = []
    monkeypatch.setattr(service, "send_research_inquiry_notification", lambda *a, **kw: calls.append(kw["inquiry_id"]) or "test-receipt")
    with Session(engine) as db:
        inquiry_id = service.create(db, ResearchInquiryCreate.model_validate(payload())).inquiry_id
    barrier = Barrier(2)
    def notify():
        with Session(engine) as db:
            row = db.get(ResearchInquiry, inquiry_id)
            barrier.wait(timeout=10)
            return service.notify(db, row)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: notify(), range(2)))
    assert results == [True, True] and calls == [inquiry_id]
    with Session(engine) as db:
        assert db.get(ResearchInquiry, inquiry_id).notification_attempts == 1


def test_application_startup_and_http_commit_against_migrated_mysql(database, monkeypatch):
    from fastapi.testclient import TestClient
    from app.db.session import get_db
    main = importlib.import_module("app.main")
    engine, _ = migrate(database)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(main, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(settings, "AUTH_STARTUP_SCHEMA_MODE", "validate")
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_ENABLED", True)
    monkeypatch.setattr(routes, "_rate_limit", lambda _: None)
    def get_test_db():
        with Session(engine) as db:
            yield db
    prior = main.app.dependency_overrides[get_db]
    main.app.dependency_overrides[get_db] = get_test_db
    try:
        with TestClient(main.app) as client:
            assert client.get("/health").status_code == 200
            before = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
            response = client.post("/api/v1/research-inquiries", json=payload())
            assert response.status_code == 201
            with Session(engine) as db:
                row = db.get(ResearchInquiry, response.json()["inquiry_id"])
                assert row and row.submission_timestamp >= before
                assert row.consent_timestamp == row.submission_timestamp
                assert response.json()["submitted_at"] == row.submission_timestamp.isoformat() + "Z"
                assert row.notification_status == "not_configured"
    finally:
        main.app.dependency_overrides[get_db] = prior


def test_real_redis_atomic_limit_expiry_and_multiple_ips(monkeypatch):
    host = os.environ.get("RESEARCH_TEST_REDIS_HOST", "127.0.0.1")
    port = os.environ.get("RESEARCH_TEST_REDIS_PORT", "")
    assert port.isdigit(), "Set RESEARCH_TEST_REDIS_PORT to a disposable Redis container"
    backend = redis.Redis(host=host, port=int(port), decode_responses=True)
    assert backend.ping()
    monkeypatch.setattr(rate_limit, "_redis", backend)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_RATE_LIMIT", 2)
    import hashlib
    for ip in ("198.51.100.11", "198.51.100.12"):
        subject = hashlib.sha256(ip.encode()).hexdigest()
        backend.delete("research-inquiry:rate:" + subject, "research-inquiry:lock:" + subject)
    request = Request({"type": "http", "client": ("198.51.100.11", 80), "headers": []})
    other = Request({"type": "http", "client": ("198.51.100.12", 80), "headers": []})
    assert routes._rate_limit(request) is None
    assert routes._rate_limit(request) is None
    assert routes._rate_limit(request).status_code == 429
    assert routes._rate_limit(other) is None
    import hashlib
    subject = hashlib.sha256(b"198.51.100.11").hexdigest()
    for prefix in ["research-inquiry:rate:", "research-inquiry:lock:"]:
        key = prefix + subject
        assert backend.ttl(key) > 0
        backend.pexpireat(key, 1)
    assert routes._rate_limit(request) is None
    backend.close()
