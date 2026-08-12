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
SESSION_TABLES = {"sessions"}  # Phase 4 PR-A (0018)
INTERACTION_TABLES = {"interactions"}  # PR-B2 (0019)
ORG_SAML_TABLES = {"organization_saml_configs"}  # SAML SSO PR2 (0021)
ALL_TABLES = (
    BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES | AUDIT_TABLES
    | MFA_TABLES | MFA_ORG_POLICY_TABLES | SESSION_TABLES | INTERACTION_TABLES | ORG_SAML_TABLES
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

    session_columns = {c["name"] for c in inspector.get_columns("sessions")}
    assert {
        "id", "session_id", "user_id", "organization_id", "org_role", "auth_method",
        "mfa_verified", "status", "created_at", "last_activity_at", "expires_at",
        "revoked_at", "revoked_reason", "client_ip", "user_agent",
    } <= session_columns
    session_uqs = inspector.get_unique_constraints("sessions")
    session_indexes = inspector.get_indexes("sessions")
    assert any(
        set(idx["column_names"]) == {"session_id"} and idx.get("unique")
        for idx in session_indexes
    ) or any(set(uq["column_names"]) == {"session_id"} for uq in session_uqs)

    interaction_columns = {c["name"] for c in inspector.get_columns("interactions")}
    assert {
        "id", "interaction_id", "organization_id", "user_id", "session_id", "trace_id",
        "service", "interaction_type", "action", "resource_type", "resource_id",
        "status", "decision", "metadata", "created_at",
    } <= interaction_columns
    interaction_uqs = inspector.get_unique_constraints("interactions")
    interaction_indexes = inspector.get_indexes("interactions")
    assert any(
        set(idx["column_names"]) == {"interaction_id"} and idx.get("unique")
        for idx in interaction_indexes
    ) or any(set(uq["column_names"]) == {"interaction_id"} for uq in interaction_uqs)
    assert any(
        set(idx["column_names"]) == {"organization_id", "created_at"} for idx in interaction_indexes
    )
    assert any(
        set(idx["column_names"]) == {"user_id", "created_at"} for idx in interaction_indexes
    )
    assert any(
        set(idx["column_names"]) == {"session_id", "created_at"} for idx in interaction_indexes
    )
    assert any(set(idx["column_names"]) == {"trace_id"} for idx in interaction_indexes)

    teams_columns = {c["name"] for c in inspector.get_columns("teams")}
    assert {"description", "created_by_user_id"} <= teams_columns

    team_membership_columns = {c["name"] for c in inspector.get_columns("team_memberships")}
    assert {"role", "invited_by_user_id", "joined_at"} <= team_membership_columns

    org_saml_columns = {c["name"] for c in inspector.get_columns("organization_saml_configs")}
    assert {
        "id", "organization_id", "entity_id", "sso_url", "x509_certificate",
        "attribute_mapping", "enabled", "status", "created_at", "updated_at", "updated_by_user_id",
    } <= org_saml_columns
    org_saml_uqs = inspector.get_unique_constraints("organization_saml_configs")
    assert any(uq["column_names"] == ["organization_id"] for uq in org_saml_uqs)


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
    assert recorded == "0021_organization_saml_config"


def test_sqlite_0019_is_purely_additive_existing_session_rows_survive(sqlite_db_url):
    """PR-B2's specific concern: 0019 creates a new table only -- it must
    not touch any existing table. A session row created under 0018 (pre-
    0019) must come out the other side of `upgrade head` completely
    unchanged, and the interactions table must exist and be empty."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0018_session_foundation")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (email, hashed_password, status) VALUES (:e, :h, :s)"),
                     {"e": "pre-b2@omnibioai.test", "h": "not-a-real-hash", "s": "active"})
        conn.execute(
            text(
                "INSERT INTO sessions (session_id, user_id, mfa_verified, status, "
                "created_at, last_activity_at, expires_at) "
                "VALUES (:sid, 1, 1, 'active', :now, :now, :exp)"
            ),
            {"sid": "pre-b2-session", "now": "2026-08-09 00:00:00", "exp": "2026-08-16 00:00:00"},
        )

    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT session_id, status FROM sessions WHERE session_id = :sid"),
            {"sid": "pre-b2-session"},
        ).mappings().one()
        interaction_count = conn.execute(text("SELECT COUNT(*) FROM interactions")).scalar()

    assert row["session_id"] == "pre-b2-session"
    assert row["status"] == "active"
    assert interaction_count == 0


def test_sqlite_0019_downgrade_drops_only_interactions(sqlite_db_url):
    """Downgrading past 0019 must remove interactions and leave every
    other table (in particular sessions, the immediately preceding
    migration) intact."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0018_session_foundation")

    engine = create_engine(sqlite_db_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert "interactions" not in tables
    assert "sessions" in tables


def test_sqlite_0020_pre_existing_team_membership_row_backfills_member_role(sqlite_db_url):
    """Team Management v0.8.0 Step 1's specific concern: a team_memberships
    row created before this migration (no role/invited_by_user_id/
    joined_at columns existed yet) must come out the other side with
    role='member' -- never 'admin' -- and both new nullable columns NULL.
    No pre-existing member's privilege silently increases as a side
    effect of adding the role column."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0019_interactions")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (email, hashed_password, status) VALUES (:e, :h, :s)"),
            {"e": "pre-0020@omnibioai.test", "h": "not-a-real-hash", "s": "active"},
        )
        conn.execute(
            text("INSERT INTO organizations (slug, name) VALUES (:slug, :name)"),
            {"slug": "pre-0020-org", "name": "Pre 0020 Org"},
        )
        conn.execute(
            text("INSERT INTO teams (organization_id, name) VALUES (1, :name)"),
            {"name": "Pre-existing Team"},
        )
        conn.execute(text("INSERT INTO team_memberships (team_id, user_id) VALUES (1, 1)"))

    command.upgrade(cfg, "head")

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT role, invited_by_user_id, joined_at FROM team_memberships WHERE team_id=1 AND user_id=1")
        ).mappings().one()
        team_row = conn.execute(
            text("SELECT description, created_by_user_id FROM teams WHERE id=1")
        ).mappings().one()

    assert row["role"] == "member"
    assert row["invited_by_user_id"] is None
    assert row["joined_at"] is None
    assert team_row["description"] is None
    assert team_row["created_by_user_id"] is None


def test_sqlite_0020_downgrade_drops_only_the_new_columns(sqlite_db_url):
    """Downgrading past 0020 must remove exactly the columns it added
    (teams.description/created_by_user_id,
    team_memberships.role/invited_by_user_id/joined_at) and leave both
    tables -- and every row in them -- otherwise intact."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (email, hashed_password, status) VALUES (:e, :h, :s)"),
            {"e": "post-0020@omnibioai.test", "h": "not-a-real-hash", "s": "active"},
        )
        conn.execute(
            text("INSERT INTO organizations (slug, name) VALUES (:slug, :name)"),
            {"slug": "post-0020-org", "name": "Post 0020 Org"},
        )
        conn.execute(
            text("INSERT INTO teams (organization_id, name, description) VALUES (1, :name, :d)"),
            {"name": "Surviving Team", "d": "will be dropped, not the row"},
        )
        conn.execute(
            text("INSERT INTO team_memberships (team_id, user_id, role) VALUES (1, 1, 'admin')")
        )

    command.downgrade(cfg, "0019_interactions")

    inspector = inspect(engine)
    teams_columns = {c["name"] for c in inspector.get_columns("teams")}
    team_membership_columns = {c["name"] for c in inspector.get_columns("team_memberships")}
    assert not {"description", "created_by_user_id"} & teams_columns
    assert not {"role", "invited_by_user_id", "joined_at"} & team_membership_columns

    with engine.connect() as conn:
        team_count = conn.execute(text("SELECT COUNT(*) FROM teams WHERE name='Surviving Team'")).scalar()
        membership_count = conn.execute(
            text("SELECT COUNT(*) FROM team_memberships WHERE team_id=1 AND user_id=1")
        ).scalar()
    assert team_count == 1
    assert membership_count == 1


def test_sqlite_0021_creates_organization_saml_configs_table(sqlite_db_url):
    """SAML SSO PR2's specific concern: a brand-new table only -- must not
    touch any existing table, and must land with exactly the columns/
    unique constraint the ORM's OrganizationSAMLConfig class declares."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "0020_team_member_roles")

    engine = create_engine(sqlite_db_url)
    inspector = inspect(engine)
    assert "organization_saml_configs" not in set(inspector.get_table_names())

    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    assert "organization_saml_configs" in set(inspector.get_table_names())
    columns = {c["name"] for c in inspector.get_columns("organization_saml_configs")}
    assert {
        "id", "organization_id", "entity_id", "sso_url", "x509_certificate",
        "attribute_mapping", "enabled", "status", "created_at", "updated_at", "updated_by_user_id",
    } <= columns
    uqs = inspector.get_unique_constraints("organization_saml_configs")
    assert any(uq["column_names"] == ["organization_id"] for uq in uqs)


def test_sqlite_0021_downgrade_drops_only_the_new_table(sqlite_db_url):
    """Downgrading past 0021 must remove organization_saml_configs and
    leave every other table (in particular teams/team_memberships, the
    immediately preceding migration's own tables) intact."""
    cfg = _alembic_config(sqlite_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(sqlite_db_url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO organizations (slug, name) VALUES (:slug, :name)"),
            {"slug": "pre-0021-org", "name": "Pre 0021 Org"},
        )
        conn.execute(
            text(
                "INSERT INTO organization_saml_configs "
                "(organization_id, entity_id, sso_url, x509_certificate, enabled, status) "
                "VALUES (1, 'https://idp.example.com/metadata', 'https://idp.example.com/sso', "
                "'-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----', 0, 'pending_verification')"
            )
        )

    command.downgrade(cfg, "0020_team_member_roles")

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert "organization_saml_configs" not in tables
    assert "teams" in tables
    assert "team_memberships" in tables

    with engine.connect() as conn:
        org_count = conn.execute(text("SELECT COUNT(*) FROM organizations WHERE slug='pre-0021-org'")).scalar()
    assert org_count == 1


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


def test_mysql_pre_existing_role_rows_survive_0016_as_platform_wide(mysql_db_url):
    """MySQL-specific regression for the 2026-08-06 incident: a real
    deployment's database was found stamped at 0015_refresh_token_length
    with `0016_role_org_scope` never applied, crash-looping the service
    against `roles.organization_id`. This is the dialect that actually
    happened against (SQLite's equivalent above didn't reproduce it --
    MySQL is where `batch_alter_table`'s FK/index drop ordering, called
    out in the migration's own downgrade() docstring, actually matters).
    Confirms 0016 applies cleanly on top of 0015 with a real pre-existing
    role row present, and that row survives as organization_id=NULL --
    exactly what was verified against the affected deployment's data
    (254 users, 4 roles, all preserved) after remediation."""
    cfg = _alembic_config(mysql_db_url)
    command.upgrade(cfg, "0015_refresh_token_length")

    engine = create_engine(mysql_db_url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO roles (name, description) VALUES (:name, :description)"),
            {"name": "pre-pr13-role", "description": "existed before 0016"},
        )

    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    roles_columns = {c["name"] for c in inspector.get_columns("roles")}
    assert "organization_id" in roles_columns

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, description, organization_id FROM roles WHERE name = :name"),
            {"name": "pre-pr13-role"},
        ).mappings().one()

    assert row["description"] == "existed before 0016"
    assert row["organization_id"] is None

    with engine.connect() as conn:
        recorded = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert recorded == "0021_organization_saml_config"


def test_mysql_0020_pre_existing_team_membership_row_backfills_member_role(mysql_db_url):
    """Dialect-specific regression coverage, same reasoning as
    test_mysql_pre_existing_role_rows_survive_0016_as_platform_wide above:
    adding a NOT NULL column with a server_default to an existing,
    composite-primary-key table (team_memberships has no surrogate id,
    unlike roles) via batch_alter_table is exactly the kind of DDL SQLite
    alone can mask. Confirms a pre-existing membership row backfills to
    role='member' against real MySQL, not just SQLite."""
    cfg = _alembic_config(mysql_db_url)
    command.upgrade(cfg, "0019_interactions")

    engine = create_engine(mysql_db_url)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (email, hashed_password, status) VALUES (:e, :h, :s)"),
            {"e": "pre-0020-mysql@omnibioai.test", "h": "not-a-real-hash", "s": "active"},
        )
        conn.execute(
            text("INSERT INTO organizations (slug, name) VALUES (:slug, :name)"),
            {"slug": "pre-0020-mysql-org", "name": "Pre 0020 MySQL Org"},
        )
        conn.execute(
            text("INSERT INTO teams (organization_id, name) VALUES (1, :name)"),
            {"name": "Pre-existing MySQL Team"},
        )
        conn.execute(text("INSERT INTO team_memberships (team_id, user_id) VALUES (1, 1)"))

    command.upgrade(cfg, "head")

    inspector = inspect(engine)
    team_membership_columns = {c["name"] for c in inspector.get_columns("team_memberships")}
    assert {"role", "invited_by_user_id", "joined_at"} <= team_membership_columns

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT role, invited_by_user_id, joined_at FROM team_memberships WHERE team_id=1 AND user_id=1")
        ).mappings().one()

    assert row["role"] == "member"
    assert row["invited_by_user_id"] is None
    assert row["joined_at"] is None


def test_mysql_interaction_id_unique_constraint_enforced(mysql_db_url):
    """PR-B2 Section 24's explicit requirement: confirm interaction_id
    UNIQUE actually works against real MySQL, not merely SQLite (whose
    constraint-enforcement semantics can differ)."""
    cfg = _alembic_config(mysql_db_url)
    command.upgrade(cfg, "head")

    engine = create_engine(mysql_db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO interactions "
                "(interaction_id, organization_id, service, interaction_type, action, created_at) "
                "VALUES (:iid, 1, 'rag', 'query', 'search', :now)"
            ),
            {"iid": "mysql-unique-test-1", "now": "2026-08-09 00:00:00"},
        )

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO interactions "
                    "(interaction_id, organization_id, service, interaction_type, action, created_at) "
                    "VALUES (:iid, 2, 'rag', 'query', 'search-again', :now)"
                ),
                {"iid": "mysql-unique-test-1", "now": "2026-08-09 00:00:01"},
            )
