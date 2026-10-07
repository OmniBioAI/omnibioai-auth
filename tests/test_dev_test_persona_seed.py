"""Regression coverage for app/db/init_admin.py::ensure_dev_test_personas.

Exercises the real bootstrap sequence (create_admin -> ensure_default_
organization -> ensure_dev_test_personas, the order app/main.py calls them
in) against a throwaway SQLite database -- never the app's own configured
database or conftest.py's shared test.db. Mirrors
test_platform_owner_bootstrap.py's own fresh_engine convention.

The one property every test here protects: SEED_DEV_TEST_PERSONAS is
opt-in. Unset, this whole mechanism is inert and creates nobody.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db.models  # noqa: F401 -- registers every ORM class on Base.metadata
from app.db.base import Base
from app.db.init_admin import create_admin, ensure_default_organization, ensure_dev_test_personas
from app.db.models import OrganizationMembership, User


@pytest.fixture
def db_session(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'dev_test_personas.db'}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _bootstrap(db, monkeypatch, password="regression-test-password-not-for-prod"):
    """The subset of app/main.py's real startup sequence this persona seed
    depends on, in the exact order app/main.py runs them."""
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", password)
    create_admin(db)
    ensure_default_organization(db)


def test_unset_env_var_creates_nobody(db_session, monkeypatch):
    monkeypatch.delenv("SEED_DEV_TEST_PERSONAS", raising=False)
    _bootstrap(db_session, monkeypatch)

    ensure_dev_test_personas(db_session)

    assert db_session.query(User).filter(User.email == "user@omnibioai.org").first() is None


@pytest.mark.parametrize("flag_value", ["true", "1", "yes", "TRUE"])
def test_opt_in_creates_passwordless_active_user_with_default_role_and_org_membership(
    db_session, monkeypatch, flag_value
):
    monkeypatch.setenv("SEED_DEV_TEST_PERSONAS", flag_value)
    _bootstrap(db_session, monkeypatch)

    ensure_dev_test_personas(db_session)

    user = db_session.query(User).filter(User.email == "user@omnibioai.org").first()
    assert user is not None
    assert user.status == "active"
    assert user.hashed_password is None
    assert {r.name for r in user.roles} == {"user"}

    membership = (
        db_session.query(OrganizationMembership)
        .filter(OrganizationMembership.user_id == user.id)
        .first()
    )
    assert membership is not None
    assert membership.status == "active"
    assert {r.name for r in membership.roles} == {"org_member"}


def test_idempotent_rerun_does_not_duplicate_or_mutate(db_session, monkeypatch):
    monkeypatch.setenv("SEED_DEV_TEST_PERSONAS", "true")
    _bootstrap(db_session, monkeypatch)

    ensure_dev_test_personas(db_session)
    first = db_session.query(User).filter(User.email == "user@omnibioai.org").first()
    first_id = first.id

    # A second startup (e.g. a container restart) must not duplicate the
    # account, re-assign roles, or touch anything already present.
    ensure_dev_test_personas(db_session)

    users = db_session.query(User).filter(User.email == "user@omnibioai.org").all()
    assert len(users) == 1
    assert users[0].id == first_id


def test_does_not_touch_existing_admin_or_other_accounts(db_session, monkeypatch):
    """Guards against the one outcome the mission explicitly forbids:
    this function must never create or touch admin@omnibioai.org, and must
    never touch the existing admin@omnibioai bootstrap account."""
    monkeypatch.setenv("SEED_DEV_TEST_PERSONAS", "true")
    _bootstrap(db_session, monkeypatch)
    admin_before = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    admin_roles_before = {r.name for r in admin_before.roles}

    ensure_dev_test_personas(db_session)

    assert db_session.query(User).filter(User.email == "admin@omnibioai.org").first() is None
    admin_after = db_session.query(User).filter(User.email == "admin@omnibioai").first()
    assert {r.name for r in admin_after.roles} == admin_roles_before
