"""Fail-fast comparison of Auth ORM tables/columns to database structure.

Production startup calls this with ``require_all_tables=True`` after the
separate Alembic revision check. It performs metadata reads only and never
creates or alters schema. The optional default preserves the narrower legacy
behavior for callers that intentionally validate only tables already present.
"""

from sqlalchemy import inspect
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData


class SchemaDriftError(RuntimeError):
    """Raised when the live database is missing columns the application's
    ORM models expect on a table that already exists -- almost always
    because an Alembic migration exists in code but hasn't been applied
    against this database yet. See docs/MIGRATIONS.md."""


def assert_schema_matches_models(
    engine: Engine,
    metadata: MetaData,
    *,
    require_all_tables: bool = False,
) -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    missing_tables: list[str] = []
    missing_by_table: dict[str, list[str]] = {}
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            if require_all_tables:
                missing_tables.append(table.name)
            continue

        actual_columns = {c["name"] for c in inspector.get_columns(table.name)}
        expected_columns = {c.name for c in table.columns}
        missing = sorted(expected_columns - actual_columns)
        if missing:
            missing_by_table[table.name] = missing

    if not missing_tables and not missing_by_table:
        return

    details = []
    if missing_tables:
        details.append(f"missing tables {sorted(missing_tables)}")
    details.extend(
        f"{table}: missing columns {cols}"
        for table, cols in sorted(missing_by_table.items())
    )
    detail = "; ".join(details)
    raise SchemaDriftError(
        "Database schema does not satisfy the application models "
        f"({detail}). This means an Alembic migration exists in code but "
        "has not been applied against this database yet. Run "
        "`alembic upgrade head` against the target database (see "
        "docs/MIGRATIONS.md / docs/DEPLOYMENT_CHECKLIST.md) before "
        "starting this service. Refusing to start rather than crash "
        "mid-bootstrap against a missing column."
    )
