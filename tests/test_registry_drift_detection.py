"""PR6 (Enterprise IAM Foundation): role_service.assert_no_unregistered_
permissions -- the startup registry/database drift check wired into
app/main.py's bootstrap sequence.

Deliberately uses its own throwaway in-memory SQLite database rather than
the shared tests/conftest.py test.db: test_permission_parity.py and
test_backfill_default_org.py intentionally create off-registry Permission
rows (e.g. "read:samples") via role_service.get_or_create_role (a call
path PR4 never validated -- see those files for why). Those rows are real
and permanent for the rest of the shared test session, so a "the whole
database currently has zero drift" assertion against the shared test.db
would be order-dependent and, in practice, false once those other test
files have run. An isolated database sidesteps that entirely and tests
assert_no_unregistered_permissions's actual logic deterministically.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Permission
from app.services.role_service import assert_no_unregistered_permissions


def _fresh_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_no_drift_when_all_permissions_are_registered():
    db = _fresh_session()
    try:
        db.add(Permission(name="manage_org"))
        db.add(Permission(name="billing.read"))
        db.commit()
        assert_no_unregistered_permissions(db)  # must not raise
    finally:
        db.close()


def test_no_drift_on_empty_permission_table():
    db = _fresh_session()
    try:
        assert_no_unregistered_permissions(db)  # must not raise
    finally:
        db.close()


def test_drift_detected_raises_runtime_error():
    db = _fresh_session()
    try:
        db.add(Permission(name="manage_org"))
        db.add(Permission(name="totally_unregistered_permission"))
        db.commit()
        try:
            assert_no_unregistered_permissions(db)
            assert False, "expected RuntimeError"
        except RuntimeError as e:
            assert "totally_unregistered_permission" in str(e)
    finally:
        db.close()


def test_drift_error_lists_all_unregistered_names():
    db = _fresh_session()
    try:
        db.add(Permission(name="bad_one"))
        db.add(Permission(name="bad_two"))
        db.commit()
        try:
            assert_no_unregistered_permissions(db)
            assert False, "expected RuntimeError"
        except RuntimeError as e:
            assert "bad_one" in str(e)
            assert "bad_two" in str(e)
    finally:
        db.close()
