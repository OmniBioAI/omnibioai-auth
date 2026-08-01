#!/usr/bin/env python3
"""Post-migration verification: confirm a database's recorded Alembic
revision and actual table set match what a given revision should produce.

Deliberately standalone (only needs sqlalchemy, already a dependency) so it
can run as a deploy-gate step against any target database without importing
the FastAPI app itself. See docs/DEPLOYMENT_CHECKLIST.md for when to run this.

Usage:
    python scripts/verify_schema.py --expect-revision 0001_baseline
    python scripts/verify_schema.py --expect-revision head
    python scripts/verify_schema.py --expect-revision head --database-url mysql+pymysql://...

Exit code 0 on success, 1 on any mismatch -- safe to use as a CI/deploy gate.
"""

import argparse
import sys
from pathlib import Path

# Running this as a plain script (not via pytest, which sets pythonpath
# correctly) puts only this file's own directory on sys.path, not the repo
# root -- `import app...` then falls through to whatever else is on
# sys.path, which on a dev machine with several sibling omnibioai-* repos
# pip-installed editable (each also using the generic top-level package
# name "app") can silently resolve to a DIFFERENT repo's app.core.config.
# Explicit insert at position 0 guarantees this repo's own app/ wins.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, inspect, text

# Cumulative table set introduced by each revision. "head" here means
# 0006_sso_enforcement_override, the newest revision as of this script's
# writing -- update this manifest when new revisions are added.
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

REVISION_TABLES = {
    "0001_baseline": BASELINE_TABLES,
    "0002_multi_tenant_schema": BASELINE_TABLES | MULTI_TENANT_TABLES,
    "0003_oauth_clients": BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES,
    "0004_org_sso_schema": BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES,
    "0005_org_sso_operational_fields": BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES,
    "0006_sso_enforcement_override": BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES,
    "head": BASELINE_TABLES | MULTI_TENANT_TABLES | OAUTH_CLIENTS_TABLES | ORG_SSO_TABLES,
}

# Columns added to license_keys by 0002 -- checked separately since the
# table itself already exists as of 0001.
LICENSE_KEYS_0002_COLUMNS = {"organization_id", "machine_id", "max_devices"}

# Column added to oauth_accounts by 0004 -- same reasoning as above.
OAUTH_ACCOUNTS_0004_COLUMNS = {"organization_sso_config_id"}

# Columns added to organization_sso_configs by 0005 -- same reasoning as above.
ORG_SSO_CONFIGS_0005_COLUMNS = {"last_verified_at", "verification_error"}

# Columns added to organization_sso_configs by 0006 -- same reasoning as above.
ORG_SSO_CONFIGS_0006_COLUMNS = {"sso_override_at", "sso_override_reason", "sso_override_by_user_id"}


def _database_url(cli_url: str | None) -> str:
    if cli_url:
        return cli_url
    # Deferred import: only needed when falling back to the app's own
    # config, so this script has no hard dependency on the app package.
    from app.core.config import settings

    return settings.DATABASE_URL


def check_alembic_revision(engine, expect_revision: str) -> list[str]:
    errors = []
    inspector = inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        errors.append(
            "alembic_version table does not exist -- this database has never "
            "had a migration applied or stamped."
        )
        return errors

    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()

    if not rows:
        errors.append("alembic_version table exists but has no revision recorded.")
        return errors

    recorded = {r[0] for r in rows}
    if expect_revision == "head":
        # "head" is a moving target by design -- accept whatever the newest
        # known revision id is, resolved by the caller via REVISION_TABLES.
        expected_ids = {rid for rid in REVISION_TABLES if rid != "head"}
        if not recorded & expected_ids:
            errors.append(
                f"alembic_version recorded {recorded!r}, expected one of "
                f"the known revisions {expected_ids!r} for 'head'."
            )
    elif expect_revision not in recorded:
        errors.append(
            f"alembic_version recorded {recorded!r}, expected {expect_revision!r}."
        )

    return errors


def check_tables(engine, expect_revision: str) -> list[str]:
    errors = []
    expected_tables = REVISION_TABLES.get(expect_revision)
    if expected_tables is None:
        errors.append(
            f"Unknown revision {expect_revision!r} -- update REVISION_TABLES "
            "in this script if a new migration was added."
        )
        return errors

    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names())
    missing = expected_tables - actual_tables
    if missing:
        errors.append(f"Missing expected tables: {sorted(missing)}")

    if expect_revision in ("0002_multi_tenant_schema", "head") and "license_keys" in actual_tables:
        actual_columns = {c["name"] for c in inspector.get_columns("license_keys")}
        missing_cols = LICENSE_KEYS_0002_COLUMNS - actual_columns
        if missing_cols:
            errors.append(f"license_keys missing expected columns: {sorted(missing_cols)}")

    if expect_revision in ("0004_org_sso_schema", "head") and "oauth_accounts" in actual_tables:
        actual_columns = {c["name"] for c in inspector.get_columns("oauth_accounts")}
        missing_cols = OAUTH_ACCOUNTS_0004_COLUMNS - actual_columns
        if missing_cols:
            errors.append(f"oauth_accounts missing expected columns: {sorted(missing_cols)}")

    if expect_revision in ("0005_org_sso_operational_fields", "head") and "organization_sso_configs" in actual_tables:
        actual_columns = {c["name"] for c in inspector.get_columns("organization_sso_configs")}
        missing_cols = ORG_SSO_CONFIGS_0005_COLUMNS - actual_columns
        if missing_cols:
            errors.append(f"organization_sso_configs missing expected columns: {sorted(missing_cols)}")

    if expect_revision in ("0006_sso_enforcement_override", "head") and "organization_sso_configs" in actual_tables:
        actual_columns = {c["name"] for c in inspector.get_columns("organization_sso_configs")}
        missing_cols = ORG_SSO_CONFIGS_0006_COLUMNS - actual_columns
        if missing_cols:
            errors.append(f"organization_sso_configs missing expected columns: {sorted(missing_cols)}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-revision",
        required=True,
        choices=list(REVISION_TABLES),
        help="Revision the target database should be at.",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="SQLAlchemy database URL. Defaults to app.core.config.settings.DATABASE_URL.",
    )
    args = parser.parse_args()

    engine = create_engine(_database_url(args.database_url))

    errors = []
    errors += check_alembic_revision(engine, args.expect_revision)
    errors += check_tables(engine, args.expect_revision)

    if errors:
        print(f"FAIL -- schema verification failed for revision {args.expect_revision!r}:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"OK -- database matches expected schema for revision {args.expect_revision!r}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
