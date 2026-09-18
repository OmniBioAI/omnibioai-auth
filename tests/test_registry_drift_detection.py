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

Developer: Manish Kumar <manish@omnibioai.org>
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
    """assert_no_unregistered_permissions does not raise when every stored permission is in the
    registry.
    """
    db = _fresh_session()
    try:
        db.add(Permission(name="manage_org"))
        db.add(Permission(name="billing.read"))
        db.commit()
        assert_no_unregistered_permissions(db)  # must not raise
    finally:
        db.close()


def test_no_drift_on_empty_permission_table():
    """assert_no_unregistered_permissions does not raise when the permission table is empty."""
    db = _fresh_session()
    try:
        assert_no_unregistered_permissions(db)  # must not raise
    finally:
        db.close()


def test_drift_detected_raises_runtime_error():
    """assert_no_unregistered_permissions raises RuntimeError naming a stored permission that is not
    in the registry.
    """
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
    """The drift RuntimeError names every unregistered permission, not just the first."""
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
