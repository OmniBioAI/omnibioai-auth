"""Startup fail-fast guard against ORM/database schema drift.

Context (2026-08-06 incident): `Base.metadata.create_all(bind=engine)`
(see `app/main.py`) only ever issues `CREATE TABLE IF NOT EXISTS` --
for a table that already exists, it does *nothing*, even if the ORM's
Python-side Column definitions have since gained new columns via an
Alembic migration nobody has run yet against this particular database.
`roles.organization_id` (added by `alembic/versions/0016_role_org_scope.py`)
is exactly this: `create_all()` silently succeeded at startup while the
live `roles` table was still missing the column, and the first query
that actually referenced it (`get_or_create_role` in bootstrap) blew up
with a raw `pymysql.err.OperationalError` deep inside SQLAlchemy --
a confusing crash-loop with no indication of what to actually do about
it. See docs/MIGRATIONS.md for the full write-up.

This module closes that gap generically: right after `create_all()`,
before any bootstrap code runs a query against a table that might be
missing columns, walk every table already present in the database and
diff its actual columns against what the corresponding ORM class
declares. Any table that already existed but is missing a column the
current code expects means exactly one thing -- an Alembic migration
has not been applied against this database yet -- and we refuse to
continue past that point with a clear, actionable message instead of
letting bootstrap crash on whichever query happens to touch the
missing column first.

Deliberately does NOT run migrations itself, and deliberately does not
consult Alembic's `alembic_version` bookkeeping table at all -- this is
a pure "does the live schema already satisfy what the code needs"
check, independent of *how* it got that way. That keeps it correct for
every environment this repo supports: a freshly created database (test
suites' `Base.metadata.create_all()` on an empty SQLite file always
produces a schema that matches the ORM exactly, so this is a no-op
there) as well as a long-lived production database that's supposed to
be kept in sync via `alembic upgrade head` per docs/MIGRATIONS.md.

A table that doesn't exist at all yet is left alone here -- that's
`create_all()`'s job (for a genuinely fresh table) or a pending
migration's (for one Alembic manages); this guard only flags tables
that exist but are missing columns, which is the specific failure mode
`create_all()` can never fix on its own.
"""

from sqlalchemy import inspect
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData


class SchemaDriftError(RuntimeError):
    """Raised when the live database is missing columns the application's
    ORM models expect on a table that already exists -- almost always
    because an Alembic migration exists in code but hasn't been applied
    against this database yet. See docs/MIGRATIONS.md."""


def assert_schema_matches_models(engine: Engine, metadata: MetaData) -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    missing_by_table: dict[str, list[str]] = {}
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            # Not our concern here -- create_all() just created it fresh
            # (matching today's models exactly), or a migration that
            # creates it hasn't run, which is a different, louder failure.
            continue

        actual_columns = {c["name"] for c in inspector.get_columns(table.name)}
        expected_columns = {c.name for c in table.columns}
        missing = sorted(expected_columns - actual_columns)
        if missing:
            missing_by_table[table.name] = missing

    if not missing_by_table:
        return

    detail = "; ".join(f"{table}: missing {cols}" for table, cols in sorted(missing_by_table.items()))
    raise SchemaDriftError(
        "Database schema is behind the application code -- one or more "
        "tables are missing columns the current ORM models expect "
        f"({detail}). This means an Alembic migration exists in code but "
        "has not been applied against this database yet. Run "
        "`alembic upgrade head` against the target database (see "
        "docs/MIGRATIONS.md / docs/DEPLOYMENT_CHECKLIST.md) before "
        "starting this service. Refusing to start rather than crash "
        "mid-bootstrap against a missing column."
    )
