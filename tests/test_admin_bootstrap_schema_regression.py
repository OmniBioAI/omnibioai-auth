"""Regression coverage for the 2026-08-06 auth-service crash-loop:
`roles.organization_id` (added by `alembic/versions/0016_role_org_scope.py`)
missing from a database that was never migrated past
`0015_refresh_token_length`. Exercises the real `create_admin()` bootstrap
path (`app/db/init_admin.py` -> `app/services/role_service.py`) against both
a healthy, fully-migrated schema and a reconstructed pre-0016 schema, using
throwaway SQLite databases -- never the app's own configured database or
`conftest.py`'s shared `test.db`. See docs/MIGRATIONS.md.
"""

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

import app.db.models  # noqa: F401 -- registers every ORM class on Base.metadata
from app.db.base import Base
from app.db.init_admin import create_admin
from app.db.models import User
from app.db.schema_guard import SchemaDriftError, assert_schema_matches_models
from app.services.role_service import get_or_create_role


@pytest.fixture
def fresh_engine(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'bootstrap.db'}"
    return create_engine(db_url, connect_args={"check_same_thread": False})


def _legacy_roles_table() -> MetaData:
    """The `roles` table exactly as it existed before 0016_role_org_scope
    -- no `organization_id` column."""
    metadata = MetaData()
    Table(
        "roles",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String(100)),
        Column("description", String(500)),
    )
    return metadata


# ── Role creation / bootstrap: current schema ───────────────────────────────


def test_create_admin_bootstraps_admin_user_and_role_against_current_schema(fresh_engine, monkeypatch):
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "regression-test-password-not-for-prod")
    Base.metadata.create_all(bind=fresh_engine)
    assert_schema_matches_models(fresh_engine, Base.metadata)  # sanity: fresh schema always matches

    Session = sessionmaker(bind=fresh_engine)
    db = Session()
    try:
        create_admin(db)

        admin = db.query(User).filter(User.email == "admin@omnibioai").first()
        assert admin is not None
        assert admin.status == "active"
        assert any(r.name == "admin" for r in admin.roles)

        # get_or_create_role(db, "user") is called by create_admin() itself
        # (the exact call that crashed in production) -- calling it again
        # here must find the same platform-wide role, not duplicate it.
        user_role = get_or_create_role(db, "user")
        assert user_role.name == "user"
        assert user_role.organization_id is None
    finally:
        db.close()


def test_create_admin_is_idempotent_across_repeated_startups(fresh_engine, monkeypatch):
    """Mirrors real container restarts: create_admin() runs on every
    startup and must never duplicate the admin user/role or reset the
    already-configured password."""
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "regression-test-password-not-for-prod")
    Base.metadata.create_all(bind=fresh_engine)

    Session = sessionmaker(bind=fresh_engine)
    db = Session()
    try:
        create_admin(db)
        first_hash = db.query(User).filter(User.email == "admin@omnibioai").first().hashed_password

        create_admin(db)  # simulate a second startup
        admins = db.query(User).filter(User.email == "admin@omnibioai").all()

        assert len(admins) == 1
        assert admins[0].hashed_password == first_hash  # password untouched on re-run
    finally:
        db.close()


# ── Regression: the exact pre-0016 failure mode ─────────────────────────────


def test_schema_guard_catches_pre_0016_database_before_bootstrap_runs(fresh_engine):
    """Reproduces the incident's starting state: a `roles` table created
    before 0016_role_org_scope existed. create_all() leaves it untouched
    (it already exists) while creating every other table fully, exactly
    like the real deployment. The startup guard must catch this with a
    clear, actionable message -- app/main.py calls this before any
    bootstrap query runs."""
    _legacy_roles_table().create_all(bind=fresh_engine)
    Base.metadata.create_all(bind=fresh_engine)  # no-op for roles; real for everything else

    with pytest.raises(SchemaDriftError, match="organization_id"):
        assert_schema_matches_models(fresh_engine, Base.metadata)


def test_create_admin_crashes_with_raw_operationalerror_when_guard_is_bypassed(fresh_engine):
    """Documents *why* the guard matters: without it, the same pre-0016
    database reaches create_admin() -> get_or_create_role() ->
    get_role_by_name() and fails with a raw OperationalError several
    stack frames deep -- the exact crash-loop observed in production --
    instead of the clear message the guard now produces first."""
    _legacy_roles_table().create_all(bind=fresh_engine)
    Base.metadata.create_all(bind=fresh_engine)

    Session = sessionmaker(bind=fresh_engine)
    db = Session()
    try:
        with pytest.raises(OperationalError, match="organization_id"):
            create_admin(db)  # guard intentionally skipped here
    finally:
        db.close()


def test_create_admin_succeeds_once_the_legacy_schema_is_migrated(fresh_engine, monkeypatch):
    """The other half of the regression: applying the missing migration
    (simulated here by adding the column the way 0016 does, rather than
    running Alembic itself -- alembic mechanics are covered by
    tests/test_migrations.py) resolves the guard and bootstrap alike,
    with zero data loss for whatever roles already existed."""
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "regression-test-password-not-for-prod")

    _legacy_roles_table().create_all(bind=fresh_engine)
    with fresh_engine.begin() as conn:
        from sqlalchemy import text

        conn.execute(
            text("INSERT INTO roles (name, description) VALUES (:name, :description)"),
            {"name": "pre-existing-role", "description": "created before 0016"},
        )
        conn.execute(text("ALTER TABLE roles ADD COLUMN organization_id INTEGER"))

    Base.metadata.create_all(bind=fresh_engine)
    assert_schema_matches_models(fresh_engine, Base.metadata)  # guard now passes

    Session = sessionmaker(bind=fresh_engine)
    db = Session()
    try:
        create_admin(db)  # the exact call that crashed in production

        admin = db.query(User).filter(User.email == "admin@omnibioai").first()
        assert admin is not None
        assert any(r.name == "admin" for r in admin.roles)

        from app.db.models import Role

        pre_existing = db.query(Role).filter(Role.name == "pre-existing-role").first()
        assert pre_existing is not None
        assert pre_existing.organization_id is None  # preserved, not reset
    finally:
        db.close()
