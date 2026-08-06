"""Alembic migration mechanics: exercised against an isolated throwaway
database, never against the app's own configured database (conftest.py's
SQLite `test.db`, or any real MySQL instance). See docs/MIGRATIONS.md for
the stamp-vs-upgrade distinction these tests are asserting.
"""

import importlib.util
import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parent.parent

BASELINE_TABLES = {
    "users", "roles", "permissions", "user_roles", "role_permissions",
    "refresh_tokens", "revoked_tokens", "oauth_accounts", "global_config",
    "license_keys",
}
MULTI_TENANT_TABLES = {
    "organizations", "teams", "team_memberships", "organization_memberships",
    "membership_roles", "api_keys", "organization_config",
}
OAUTH_CLIENTS_TABLES = {"oauth_clients"}
ORG_SSO_TABLES = {"organization_sso_configs"}
AUDIT_TABLES = {"audit_events"}  # PR9 (0011)
MFA_TABLES = {"mfa_devices", "mfa_recovery_codes"}  # PR11.5.1 (0013)
MFA_ORG_POLICY_TABLES = {"organization_mfa_policies"}  # PR11.5.5 (0014)
ALL_TABLES = (
    BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES | AUDIT_TABLES
    | MFA_TABLES | MFA_ORG_POLICY_TABLES
)


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # env.py only falls back to settings.DATABASE_URL when this is unset --
    # setting it here points migrations at the throwaway test DB instead of
    # whatever the app's own DB_HOST/DB_USER/etc. env vars resolve to.
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


# ---------------------------------------------------------------------------
# SQLite: always runs, no external service required.
# ---------------------------------------------------------------------------


@pytest.fixture
def sqlite_db_url(tmp_path):
    db_file = tmp_path / "migration_test.db"
    yield f"sqlite:///{db_file}"
    # tmp_path is pytest-managed and auto-cleaned; nothing else to do.


def test_sqlite_fresh_upgrade_head_creates_all_tables(sqlite_db_url):
    """From an empty database, `alembic upgrade head` must run every
    revision (0001-0011) for real and produce every expected table, plus
    license_keys' 3 Phase-1 columns, oauth_accounts' organization_sso_config_id
    column, organization_sso_configs' operational (0005) and break-glass
    override (0006) columns, refresh_tokens' rotation (0007) columns,
    organizations' status-tracking (0008) columns, users' directory fields
    (0009), roles' description column (0010), and the audit_events table
    (0011)."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sqlite_db_url)
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())

    assert ALL_TABLES <= actual_tables, f"Missing tables: {ALL_TABLES - actual_tables}"

    license_columns = {c["name"] for c in inspector.get_columns("license_keys")}
    assert {"organization_id", "machine_id", "max_devices"} <= license_columns

    oauth_account_columns = {c["name"] for c in inspector.get_columns("oauth_accounts")}
    assert "organization_sso_config_id" in oauth_account_columns

    uqs = inspector.get_unique_constraints("oauth_accounts")
    widened = next(uq for uq in uqs if uq["name"] == "uq_oauth_provider_account")
    assert set(widened["column_names"]) == {"provider", "provider_user_id", "organization_sso_config_id"}

    org_sso_columns = {c["name"] for c in inspector.get_columns("organization_sso_configs")}
    assert {"last_verified_at", "verification_error"} <= org_sso_columns
    assert {"sso_override_at", "sso_override_reason", "sso_override_by_user_id"} <= org_sso_columns

    refresh_token_columns = {c["name"] for c in inspector.get_columns("refresh_tokens")}
    assert {"family_id", "rotated_at"} <= refresh_token_columns

    organizations_columns = {c["name"] for c in inspector.get_columns("organizations")}
    assert {"status_changed_at", "status_changed_reason", "status_changed_by_user_id"} <= organizations_columns

    users_columns = {c["name"] for c in inspector.get_columns("users")}
    assert {"created_at", "status_changed_at", "status_changed_reason", "status_changed_by_user_id"} <= users_columns

    roles_columns = {c["name"] for c in inspector.get_columns("roles")}
    assert {"description", "organization_id"} <= roles_columns
    roles_uqs = inspector.get_unique_constraints("roles")
    assert not any(uq["column_names"] == ["name"] for uq in roles_uqs), (
        "roles.name's old global UNIQUE constraint should have been dropped by 0016"
    )

    audit_event_columns = {c["name"] for c in inspector.get_columns("audit_events")}
    assert {
        "id", "event_type", "actor_user_id", "target_user_id", "organization_id",
        "resource_type", "resource_id", "before_state", "after_state", "metadata", "created_at",
    } <= audit_event_columns

    users_mfa_columns = {c["name"] for c in inspector.get_columns("users")}
    assert {
        "mfa_enabled", "mfa_status", "mfa_primary_method", "mfa_enabled_at", "mfa_last_verified_at",
    } <= users_mfa_columns

    mfa_device_columns = {c["name"] for c in inspector.get_columns("mfa_devices")}
    assert {
        "id", "user_id", "device_type", "label", "encrypted_secret",
        "created_at", "verified_at", "last_used_at", "disabled_at",
    } <= mfa_device_columns

    mfa_recovery_code_columns = {c["name"] for c in inspector.get_columns("mfa_recovery_codes")}
    assert {"id", "user_id", "code_hash", "created_at", "used_at"} <= mfa_recovery_code_columns

    org_mfa_policy_columns = {c["name"] for c in inspector.get_columns("organization_mfa_policies")}
    assert {
        "id", "organization_id", "required", "created_at", "updated_at",
        "enabled_at", "enabled_by_user_id",
        "override_active", "override_reason", "override_at", "override_by_user_id",
    } <= org_mfa_policy_columns


def test_sqlite_pre_existing_user_row_survives_0013_with_correct_mfa_defaults(sqlite_db_url):
    """PR11.5.1's specific concern: a user row created *before* this
    migration ever ran (no mfa_* columns existed yet) must come out the
    other side of 0013 with mfa_enabled=False and mfa_status="disabled"
    -- not NULL, not dropped, not requiring any backfill script -- while
    every pre-existing column on that row (email, hashed_password, ...)
    is left completely unchanged. This is the concrete migration-safety
    check requested by PR11.5.1 ("existing users migrate successfully").
    """
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0012_user_login_metadata")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (email, hashed_password, status) "
                "VALUES (:email, :hashed_password, :status)"
            ),
            {"email": "pre-mfa@omnibioai.test", "hashed_password": "not-a-real-hash", "status": "active"},
        )

    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT email, hashed_password, status, mfa_enabled, mfa_status, "
                "mfa_primary_method, mfa_enabled_at, mfa_last_verified_at "
                "FROM users WHERE email = :email"
            ),
            {"email": "pre-mfa@omnibioai.test"},
        ).mappings().one()

    assert row["email"] == "pre-mfa@omnibioai.test"
    assert row["hashed_password"] == "not-a-real-hash"
    assert row["status"] == "active"
    # SQLite has no native boolean type -- server_default=sa.false() lands
    # as integer 0, same as every other Boolean column in this schema.
    assert row["mfa_enabled"] in (False, 0)
    assert row["mfa_status"] == "disabled"
    assert row["mfa_primary_method"] is None
    assert row["mfa_enabled_at"] is None
    assert row["mfa_last_verified_at"] is None


def test_sqlite_new_user_row_after_0013_has_correct_mfa_defaults(sqlite_db_url):
    """A user registered *after* this migration (going through the ORM's
    own Column(default=...), not just the migration's server_default)
    gets the identical defaults -- both write paths agree."""
    from app.db.models import User

    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sqlite_db_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        user = User(email="post-mfa@omnibioai.test", hashed_password="not-a-real-hash", status="active")
        session.add(user)
        session.commit()
        session.refresh(user)

        assert user.mfa_enabled is False
        assert user.mfa_status == "disabled"
        assert user.mfa_primary_method is None
        assert user.mfa_enabled_at is None
        assert user.mfa_last_verified_at is None
    finally:
        session.close()


def test_sqlite_downgrade_base_reverses_cleanly(sqlite_db_url):
    """Full upgrade then full downgrade must leave no application tables
    behind -- proves the migration is cleanly reversible on a throwaway DB
    (never to be run against real data, per both migration files' own
    downgrade() docstrings)."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = create_engine(sqlite_db_url)
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())

    remaining = ALL_TABLES & actual_tables
    assert not remaining, f"Tables survived downgrade to base: {remaining}"


def test_sqlite_oauth_accounts_rows_survive_the_0004_constraint_widen(sqlite_db_url):
    """Phase 2 PR2's specific concern: a pre-existing oauth_accounts row
    (created under the old 2-column unique constraint, before this
    migration ever ran) must come out the other side of 0004 unchanged in
    value, with organization_sso_config_id defaulting to NULL -- not
    dropped, not renumbered, not forced into some new required value."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0003_oauth_clients")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email) "
                "VALUES (:user_id, :provider, :provider_user_id, :email)"
            ),
            {"user_id": 1, "provider": "google", "provider_user_id": "pre-existing-uid", "email": "pre@omnibioai.test"},
        )

    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT provider, provider_user_id, email, organization_sso_config_id FROM oauth_accounts WHERE provider_user_id = :uid"),
            {"uid": "pre-existing-uid"},
        ).mappings().one()

    assert row["provider"] == "google"
    assert row["email"] == "pre@omnibioai.test"
    assert row["organization_sso_config_id"] is None


def test_sqlite_pre_existing_role_rows_survive_0016_as_platform_wide(sqlite_db_url):
    """PR13's specific concern: a role row created before this migration
    (no organization_id column existed yet) must come out the other side
    with organization_id=NULL -- i.e. every pre-existing role is a
    platform-wide role, with zero backfill required and no identity
    change (same id, same name, same permissions)."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0015_refresh_token_length")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO roles (name, description) VALUES (:name, :description)"),
                     {"name": "pre-pr13-role", "description": "existed before 0016"})

    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, description, organization_id FROM roles WHERE name = :name"),
            {"name": "pre-pr13-role"},
        ).mappings().one()

    assert row["description"] == "existed before 0016"
    assert row["organization_id"] is None


def test_sqlite_0016_downgrade_restores_global_unique_constraint(sqlite_db_url):
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0015_refresh_token_length")

    engine = create_engine(sqlite_db_url)
    inspector = inspect(engine)
    roles_columns = {c["name"] for c in inspector.get_columns("roles")}
    assert "organization_id" not in roles_columns
    roles_uqs = inspector.get_unique_constraints("roles")
    assert any(uq["column_names"] == ["name"] for uq in roles_uqs)


def _load_revision_module(filename: str):
    """Loads an Alembic revision file directly by path (its filename starts
    with a digit, so it can't be a normal dotted import) so its upgrade()
    can be invoked in isolation, without going through `alembic upgrade`
    (which would also stamp alembic_version -- see below for why that
    matters here)."""
    path = REPO_ROOT / "alembic" / "versions" / filename
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_upgrade_only(engine, module) -> None:
    """Runs a single revision's upgrade() against a connection without
    touching alembic_version at all -- used to build a "pre-Alembic"
    starting state for a test, as opposed to `command.upgrade`, which
    always records the revision it applied."""
    with engine.connect() as connection:
        ctx = MigrationContext.configure(connection)
        with ctx.begin_transaction():
            with Operations.context(ctx):
                module.upgrade()


def test_sqlite_stamp_then_upgrade_matches_real_deployment_procedure(sqlite_db_url):
    """Simulates every existing environment: tables already exist (as if
    created by the old create_all() path, before Alembic or PR2's ORM
    classes existed), with no alembic_version bookkeeping at all. Then
    0001_baseline is stamped (no DDL executed), and `alembic upgrade head`
    applies 0002 through 0010 for real. This is the exact procedure
    docs/DEPLOYMENT_CHECKLIST.md prescribes -- if this test passes,
    `alembic upgrade 0001_baseline` would NOT have (it would hit a
    duplicate-table error), which is the whole reason stamp is required.

    Deliberately builds the starting state from 0001_baseline.py's own
    upgrade() directly, not from today's live ORM classes -- the ORM's
    LicenseKey class already carries PR2's organization_id/machine_id/
    max_devices columns (correctly, since that's the current schema), so
    using it here would simulate a database that's already partway through
    0002, which is not what a real pre-existing environment looks like.
    """
    baseline_module = _load_revision_module("0001_baseline.py")
    engine = create_engine(sqlite_db_url)
    _run_upgrade_only(engine, baseline_module)

    inspector = inspect(engine)
    assert BASELINE_TABLES <= set(inspector.get_table_names())
    assert not (MULTI_TENANT_TABLES & set(inspector.get_table_names()))
    assert "alembic_version" not in inspector.get_table_names()

    cfg = _alembic_config(sqlite_db_url)
    command.stamp(cfg, "0001_baseline")
    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    assert ALL_TABLES <= actual_tables

    with engine.connect() as conn:
        recorded = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert recorded == "0016_role_org_scope"


# ---------------------------------------------------------------------------
# MySQL: runs against a throwaway database on a real MySQL server, skipped
# entirely if one isn't reachable (e.g. in a CI environment without MySQL).
# Never touches the app's actual configured database -- always a
# dedicated, dropped-before-and-after throwaway database name.
# ---------------------------------------------------------------------------

_MYSQL_HOST = os.environ.get("TEST_MYSQL_HOST", "localhost")
_MYSQL_PORT = os.environ.get("TEST_MYSQL_PORT", "3306")
_MYSQL_USER = os.environ.get("TEST_MYSQL_USER", "root")
_MYSQL_PASSWORD = os.environ.get("TEST_MYSQL_PASSWORD", "root")
_MYSQL_SERVER_URL = (
    f"mysql+pymysql://{_MYSQL_USER}:{_MYSQL_PASSWORD}@{_MYSQL_HOST}:{_MYSQL_PORT}/"
)
_THROWAWAY_DB = f"omnibioai_auth_migration_test_{uuid.uuid4().hex[:8]}"


def _mysql_reachable() -> bool:
    try:
        engine = create_engine(_MYSQL_SERVER_URL, connect_args={"connect_timeout": 2})
        with engine.connect():
            pass
        return True
    except Exception:
        return False


@pytest.fixture
def mysql_db_url():
    if not _mysql_reachable():
        pytest.skip(
            f"No MySQL server reachable at {_MYSQL_HOST}:{_MYSQL_PORT} -- "
            "skipping MySQL migration validation (SQLite coverage above still applies)."
        )

    admin_engine = create_engine(_MYSQL_SERVER_URL, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS `{_THROWAWAY_DB}`"))
        conn.execute(text(f"CREATE DATABASE `{_THROWAWAY_DB}`"))

    try:
        yield f"{_MYSQL_SERVER_URL}{_THROWAWAY_DB}"
    finally:
        with admin_engine.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS `{_THROWAWAY_DB}`"))
        admin_engine.dispose()


def test_mysql_fresh_upgrade_head_creates_all_tables(mysql_db_url):
    """Same assertion as the SQLite equivalent, but against real MySQL --
    catches dialect-specific DDL issues (JSON columns, composite primary
    keys, FK constraint creation via batch_alter_table) that SQLite alone
    would not."""
    cfg = _alembic_config(mysql_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(mysql_db_url)
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())

    assert ALL_TABLES <= actual_tables, f"Missing tables: {ALL_TABLES - actual_tables}"

    license_columns = {c["name"] for c in inspector.get_columns("license_keys")}
    assert {"organization_id", "machine_id", "max_devices"} <= license_columns


def test_mysql_downgrade_base_reverses_cleanly(mysql_db_url):
    cfg = _alembic_config(mysql_db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    engine = create_engine(mysql_db_url)
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())

    remaining = ALL_TABLES & actual_tables
    assert not remaining, f"Tables survived downgrade to base: {remaining}"
