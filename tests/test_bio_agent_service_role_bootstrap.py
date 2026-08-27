"""Regression coverage for app/db/init_admin.py::ensure_bio_agent_service_role
(#443). Mirrors test_platform_owner_bootstrap.py's exact structure --
same throwaway-SQLite-database convention, same opt-in-env-var shape,
same "additive, idempotent, audit-logged, never fabricates an account"
properties, applied to a different permission/role/env var.

The one property every test here protects: BIO_AGENT_SVC_EMAIL is
opt-in. Unset, this whole mechanism is inert -- no role, no permission
grant, for anyone.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.db.models  # noqa: F401 -- registers every ORM class on Base.metadata
from app.db.base import Base
from app.db.init_admin import create_admin, ensure_bio_agent_service_role
from app.db.models import AuditEvent, Role, User


@pytest.fixture
def db_session(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'bio_agent_service_role.db'}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _bootstrap(db, monkeypatch, password="regression-test-password-not-for-prod"):
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", password)
    create_admin(db)
    ensure_bio_agent_service_role(db)


# ── Default (opt-out) behavior ──────────────────────────────────────────────


def test_unset_env_var_creates_no_role_and_grants_nothing(db_session, monkeypatch):
    monkeypatch.delenv("BIO_AGENT_SVC_EMAIL", raising=False)
    _bootstrap(db_session, monkeypatch)

    assert db_session.query(Role).filter(Role.name == "bio_agent_service").first() is None
    assert db_session.query(AuditEvent).count() == 0


def test_blank_env_var_is_treated_the_same_as_unset(db_session, monkeypatch):
    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "   ")
    _bootstrap(db_session, monkeypatch)

    assert db_session.query(Role).filter(Role.name == "bio_agent_service").first() is None


# ── Opt-in: designates an already-existing account ──────────────────────────


def test_designates_an_existing_user(db_session, monkeypatch):
    svc = User(email="svc-bio-agent@omnibioai.internal", hashed_password="x", status="active")
    db_session.add(svc)
    db_session.commit()

    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)

    db_session.refresh(svc)
    role_names = {r.name for r in svc.roles}
    assert "bio_agent_service" in role_names

    role = db_session.query(Role).filter(Role.name == "bio_agent_service").first()
    assert {p.name for p in role.permissions} == {"service_token.mint"}


def test_grant_is_audit_logged_with_no_human_actor(db_session, monkeypatch):
    svc = User(email="svc-bio-agent@omnibioai.internal", hashed_password="x", status="active")
    db_session.add(svc)
    db_session.commit()

    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)

    events = db_session.query(AuditEvent).filter(AuditEvent.target_user_id == svc.id).all()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "role_assigned"
    assert event.actor_user_id is None  # startup, not an authenticated request
    assert event.event_metadata["source"] == "bootstrap.bio_agent_svc_email"
    assert event.event_metadata["role"] == "bio_agent_service"


def test_idempotent_across_repeated_startups(db_session, monkeypatch):
    svc = User(email="svc-bio-agent@omnibioai.internal", hashed_password="x", status="active")
    db_session.add(svc)
    db_session.commit()

    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)
    ensure_bio_agent_service_role(db_session)  # simulate a second container restart
    ensure_bio_agent_service_role(db_session)  # and a third

    db_session.refresh(svc)
    assert [r.name for r in svc.roles].count("bio_agent_service") == 1
    assert db_session.query(AuditEvent).filter(AuditEvent.target_user_id == svc.id).count() == 1


def test_env_var_with_no_matching_user_is_a_safe_no_op(db_session, monkeypatch):
    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)  # must not raise -- account doesn't exist yet

    assert db_session.query(AuditEvent).count() == 0
    # The role (carrying service_token.mint) is still created as idempotent
    # groundwork so the next startup only has to append it to the account --
    # same "safe to retry" shape as ensure_platform_owner's own
    # no-matching-user case. What must NOT happen is any user gaining the
    # grant, or any audit event firing.
    role = db_session.query(Role).filter(Role.name == "bio_agent_service").first()
    assert role is not None
    assert {p.name for p in role.permissions} == {"service_token.mint"}
    for user in db_session.query(User).all():
        assert all(r.name != "bio_agent_service" for r in user.roles)


# ── Never widens beyond the one designated account ──────────────────────────


def test_a_second_scientist_role_holder_is_not_granted_the_mint_permission(db_session, monkeypatch):
    """Confirms the least-privilege boundary this permission was designed
    for: an ordinary "scientist"-role holder must not incidentally gain
    service_token.mint just by existing alongside the real grant."""
    svc = User(email="svc-bio-agent@omnibioai.internal", hashed_password="x", status="active")
    other_scientist = User(email="researcher@example.test", hashed_password="x", status="active")
    db_session.add_all([svc, other_scientist])
    db_session.commit()

    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)

    db_session.refresh(other_scientist)
    assert all(r.name != "bio_agent_service" for r in other_scientist.roles)


def test_does_not_touch_any_other_role_the_account_already_holds(db_session, monkeypatch):
    from app.services.role_service import get_or_create_role

    svc = User(email="svc-bio-agent@omnibioai.internal", hashed_password="x", status="active")
    db_session.add(svc)
    db_session.commit()
    scientist_role = get_or_create_role(db_session, "scientist", ["workflow.execute"])
    svc.roles.append(scientist_role)
    db_session.commit()

    monkeypatch.setenv("BIO_AGENT_SVC_EMAIL", "svc-bio-agent@omnibioai.internal")
    _bootstrap(db_session, monkeypatch)

    db_session.refresh(svc)
    role_names = {r.name for r in svc.roles}
    assert role_names == {"scientist", "bio_agent_service"}
