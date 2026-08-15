"""Regression coverage for app/db/init_admin.py::ensure_platform_owner.

Exercises the real bootstrap sequence (create_admin -> ensure_platform_
admin_role -> ensure_platform_owner, the exact order app/main.py calls
them in) against a throwaway SQLite database -- never the app's own
configured database or conftest.py's shared test.db. Mirrors
test_admin_bootstrap_schema_regression.py's own fresh_engine convention.

The one property every test here protects: PLATFORM_OWNER_EMAIL is
opt-in. Unset, this whole mechanism is inert and
ensure_platform_admin_role's own pre-existing behavior ("does not assign
this role to any user -- not even the bootstrap admin@omnibioai
account") is completely unchanged.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db.models  # noqa: F401 -- registers every ORM class on Base.metadata
from app.core.permission_names import (
    PLATFORM_MANAGE_CONTENT,
    PLATFORM_MANAGE_CRON,
    PLATFORM_MANAGE_INFRA,
)
from app.db.base import Base
from app.db.init_admin import (
    create_admin,
    ensure_platform_admin_role,
    ensure_platform_owner,
)
from app.db.models import AuditEvent, Role, User
from app.services.role_service import get_or_create_role


@pytest.fixture
def db_session(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'platform_owner.db'}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _bootstrap(db, monkeypatch, password="regression-test-password-not-for-prod"):
    """The exact three-call sequence app/main.py runs at every real
    startup, in the exact order."""
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", password)
    create_admin(db)
    ensure_platform_admin_role(db)
    ensure_platform_owner(db)


# ── Default (opt-out) behavior: unchanged from before this change ──────────


def test_unset_env_var_grants_platform_admin_to_nobody(db_session, monkeypatch):
    monkeypatch.delenv("PLATFORM_OWNER_EMAIL", raising=False)
    _bootstrap(db_session, monkeypatch)

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert admin is not None
    assert all(r.name != "platform_admin" for r in admin.roles), (
        "PLATFORM_OWNER_EMAIL is unset -- platform_admin must not be "
        "granted to anyone, including the bootstrap admin"
    )
    assert db_session.query(AuditEvent).count() == 0


def test_blank_env_var_is_treated_the_same_as_unset(db_session, monkeypatch):
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "   ")
    _bootstrap(db_session, monkeypatch)

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert all(r.name != "platform_admin" for r in admin.roles)


# ── Opt-in: designates the bootstrap admin as platform owner ───────────────


def test_platform_owner_email_matching_bootstrap_admin_grants_platform_admin(db_session, monkeypatch):
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    _bootstrap(db_session, monkeypatch)

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    role_names = {r.name for r in admin.roles}
    assert "platform_admin" in role_names
    # Purely additive -- the pre-existing "admin" role/grant is untouched.
    assert "admin" in role_names


def test_grant_is_audit_logged_with_no_human_actor(db_session, monkeypatch):
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    _bootstrap(db_session, monkeypatch)

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    events = db_session.query(AuditEvent).filter(AuditEvent.target_user_id == admin.id).all()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "role_assigned"
    assert event.actor_user_id is None  # startup, not an authenticated request
    assert event.event_metadata["source"] == "bootstrap.platform_owner_email"
    assert event.event_metadata["role"] == "platform_admin"


def test_idempotent_across_repeated_startups(db_session, monkeypatch):
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    _bootstrap(db_session, monkeypatch)
    ensure_platform_owner(db_session)  # simulate a second container restart
    ensure_platform_owner(db_session)  # and a third

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert [r.name for r in admin.roles].count("platform_admin") == 1
    # No duplicate audit rows on the no-op re-runs either.
    assert db_session.query(AuditEvent).filter(AuditEvent.target_user_id == admin.id).count() == 1


def test_does_not_remove_or_touch_any_other_role(db_session, monkeypatch):
    """Purely additive, both for the target account and for the roles it
    already holds."""
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    _bootstrap(db_session, monkeypatch)

    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert any(r.name == "admin" for r in admin.roles)
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    # The pre-existing "admin" role's own permission set is untouched.
    assert {p.name for p in admin_role.permissions} == {
        "manage_roles", "manage_licenses", "manage_config", "override_sso_enforcement",
        PLATFORM_MANAGE_INFRA, PLATFORM_MANAGE_CRON, PLATFORM_MANAGE_CONTENT,
    }


# ── Opt-in: designates a different, already-existing user ──────────────────


def test_platform_owner_email_can_designate_a_non_bootstrap_user(db_session, monkeypatch):
    other = User(email="owner@example.test", hashed_password="x", status="active")
    db_session.add(other)
    db_session.commit()

    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "owner@example.test")
    _bootstrap(db_session, monkeypatch)

    db_session.refresh(other)
    assert any(r.name == "platform_admin" for r in other.roles)

    # And nobody else -- specifically not the bootstrap admin, who was
    # never named -- gets it as a side effect.
    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert all(r.name != "platform_admin" for r in admin.roles)


def test_platform_owner_email_with_no_matching_user_is_a_safe_no_op(db_session, monkeypatch, caplog):
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "nobody-has-signed-up-yet@example.test")
    _bootstrap(db_session, monkeypatch)  # must not raise

    assert db_session.query(AuditEvent).count() == 0
    admin = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert all(r.name != "platform_admin" for r in admin.roles)


def test_platform_owner_email_before_role_exists_is_a_safe_no_op(db_session, monkeypatch):
    """Startup-ordering guard: even if ensure_platform_owner were somehow
    invoked before ensure_platform_admin_role, it must not raise."""
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "regression-test-password-not-for-prod")
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    create_admin(db_session)

    ensure_platform_owner(db_session)  # platform_admin role does not exist yet

    assert db_session.query(Role).filter(Role.name == "platform_admin").first() is None
    assert db_session.query(AuditEvent).count() == 0


# ── Never widens to "every admin" ───────────────────────────────────────────


def test_second_admin_style_user_is_not_granted_platform_admin(db_session, monkeypatch):
    """A second user who separately holds the "admin" role (e.g. promoted
    later through the platform's own role-management API) must not
    inherit platform_admin just by sharing that role -- only the exact
    PLATFORM_OWNER_EMAIL match does."""
    monkeypatch.setenv("PLATFORM_OWNER_EMAIL", "admin@omnibioai")
    _bootstrap(db_session, monkeypatch)

    admin_role = get_or_create_role(db_session, "admin")
    second_admin = User(email="second-admin@example.test", hashed_password="x", status="active")
    second_admin.roles.append(admin_role)
    db_session.add(second_admin)
    db_session.commit()

    ensure_platform_owner(db_session)  # simulate the next startup

    db_session.refresh(second_admin)
    assert all(r.name != "platform_admin" for r in second_admin.roles)
