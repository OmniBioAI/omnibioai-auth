from datetime import datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import AuditEvent, Role
from app.services import audit_integrity, audit_service

TEST_KEY = "c3" * 32


def _record(**overrides):
    values = {
        "id": 17,
        "event_type": "role_created",
        "actor_user_id": None,
        "target_user_id": 0,
        "organization_id": None,
        "resource_type": "",
        "resource_id": "17",
        "before_state": None,
        "after_state": {"permissions": ["read", "write"], "name": "role"},
        "event_metadata": {},
        "created_at": datetime(2026, 9, 26, 12, 30, 1, 123456),
        "integrity_version": None,
        "integrity_algorithm": None,
        "integrity_digest": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_canonicalization_is_stable_and_json_order_independent():
    left = _record(after_state={"a": 1, "b": {"x": None, "y": ""}})
    right = _record(after_state={"b": {"y": "", "x": None}, "a": 1})
    assert audit_integrity.canonical_record(left) == audit_integrity.canonical_record(right)
    assert b'"before_state":null' in audit_integrity.canonical_record(left)
    assert b'"resource_type":""' in audit_integrity.canonical_record(left)


def test_signed_record_verifies_and_signed_field_tampering_fails():
    record = _record()
    audit_integrity.set_integrity(record, TEST_KEY)
    assert audit_integrity.verify_record(record, TEST_KEY) is audit_integrity.IntegrityResult.VALID
    record.organization_id = 9
    assert audit_integrity.verify_record(record, TEST_KEY) is audit_integrity.IntegrityResult.INVALID


def test_wrong_key_legacy_and_unsupported_version_are_classified():
    record = _record()
    audit_integrity.set_integrity(record, TEST_KEY)
    assert audit_integrity.verify_record(record, "d4" * 32) is audit_integrity.IntegrityResult.INVALID
    assert audit_integrity.verify_record(_record(), TEST_KEY) is audit_integrity.IntegrityResult.LEGACY_UNSIGNED
    record.integrity_version = 99
    assert audit_integrity.verify_record(record, TEST_KEY) is audit_integrity.IntegrityResult.UNSUPPORTED_VERSION


def test_malformed_partial_integrity_metadata_is_not_legacy():
    record = _record(integrity_digest="bad")
    assert audit_integrity.verify_record(record, TEST_KEY) is audit_integrity.IntegrityResult.UNSUPPORTED_VERSION


def test_missing_or_short_integrity_key_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_AUDIT_INTEGRITY_KEY", "")
    with pytest.raises(RuntimeError, match="missing or malformed"):
        audit_integrity.sign_record(_record())
    with pytest.raises(RuntimeError, match="256 bits"):
        audit_integrity.sign_record(_record(), "aa" * 31)


def test_transaction_bound_audit_insert_is_signed_without_committing(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUTH_AUDIT_INTEGRITY_KEY", TEST_KEY)
    engine = create_engine(f"sqlite:///{tmp_path / 'audit-integrity.db'}")
    Role.__table__.create(engine)
    AuditEvent.__table__.create(engine)
    with Session(engine) as db:
        role = Role(name="integrity-test-role")
        db.add(role)
        audit_service.log_event(
            db, "role_created", resource_type="role", resource_id="integrity-test-role",
            after_state={"name": "integrity-test-role"}, commit=False,
        )
        assert db.in_transaction()
        assert db.query(AuditEvent).count() == 1
        row = db.query(AuditEvent).one()
        assert row.integrity_version == 1
        assert row.integrity_algorithm == "HMAC-SHA-256"
        assert audit_integrity.verify_record(row) is audit_integrity.IntegrityResult.VALID
        db.rollback()
        assert db.query(Role).count() == 0
        assert db.query(AuditEvent).count() == 0
    engine.dispose()


def test_log_event_normalizes_nonzero_microseconds_before_signing_and_storage(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(settings, "AUTH_AUDIT_INTEGRITY_KEY", TEST_KEY)
    source_timestamp = datetime(2026, 9, 26, 12, 30, 1, 654321)

    class FixedDateTime:
        @staticmethod
        def utcnow():
            return source_timestamp

    monkeypatch.setattr(audit_service, "datetime", FixedDateTime)
    engine = create_engine(f"sqlite:///{tmp_path / 'audit-timestamp.db'}")
    AuditEvent.__table__.create(engine)

    with Session(engine) as db:
        audit_service.log_event(db, "timestamp_precision_regression")
        row_id = db.query(AuditEvent.id).filter_by(
            event_type="timestamp_precision_regression"
        ).scalar()

    # Verify a fresh ORM load, not the pre-insert object used to calculate
    # the original HMAC.
    with Session(engine) as db:
        reloaded = db.get(AuditEvent, row_id)
        assert reloaded.created_at == source_timestamp.replace(microsecond=0)
        assert reloaded.created_at.microsecond == 0
        assert audit_integrity.verify_record(reloaded) is audit_integrity.IntegrityResult.VALID

    engine.dispose()


def test_signing_failure_rolls_back_business_mutation(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUTH_AUDIT_INTEGRITY_KEY", "")
    engine = create_engine(f"sqlite:///{tmp_path / 'audit-sign-failure.db'}")
    Role.__table__.create(engine)
    AuditEvent.__table__.create(engine)
    with Session(engine) as db:
        db.add(Role(name="must-rollback"))
        with pytest.raises(RuntimeError, match="integrity key"):
            audit_service.log_event(db, "role_created", commit=False)
        db.rollback()
        assert db.query(Role).count() == 0
        assert db.query(AuditEvent).count() == 0
    engine.dispose()
