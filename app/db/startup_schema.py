"""Database startup policy: production validation is read-only."""

from pathlib import Path

from sqlalchemy import inspect
from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData

from app.db.revision_guard import assert_alembic_at_head
from app.db.schema_guard import assert_schema_matches_models


class StartupSchemaError(RuntimeError):
    """Raised when runtime startup sees an incomplete or incompatible schema."""


def _assert_all_tables_present(engine: Engine, metadata: MetaData) -> None:
    existing = set(inspect(engine).get_table_names())
    missing = sorted(table.name for table in metadata.sorted_tables if table.name not in existing)
    if missing:
        raise StartupSchemaError(
            f"Database is missing Auth tables {missing}; apply reviewed Alembic migrations before startup."
        )
    assert_schema_matches_models(engine, metadata)


def prepare_startup_schema(
    engine: Engine,
    metadata: MetaData,
    *,
    app_env: str,
    mode: str,
    script_location: str | Path,
) -> None:
    """Validate production schema without issuing DDL; allow creation only in tests."""
    environment = app_env.strip().lower()
    startup_mode = mode.strip().lower()

    if startup_mode == "test-create":
        if environment != "test":
            raise StartupSchemaError(
                "AUTH_STARTUP_SCHEMA_MODE=test-create is permitted only when APP_ENV=test."
            )
        metadata.create_all(bind=engine)
        _assert_all_tables_present(engine, metadata)
        return

    if startup_mode != "validate":
        raise StartupSchemaError(
            "AUTH_STARTUP_SCHEMA_MODE must be 'validate' (production) or test-only 'test-create'."
        )

    assert_alembic_at_head(engine, script_location)
    _assert_all_tables_present(engine, metadata)
