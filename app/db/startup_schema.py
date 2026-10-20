"""Auth startup schema policy: read-only validation or isolated test setup."""

from sqlalchemy.engine import Engine
from sqlalchemy.sql.schema import MetaData

from app.db.revision_guard import assert_alembic_at_head
from app.db.schema_guard import assert_schema_matches_models


def prepare_startup_schema(
    engine: Engine,
    metadata: MetaData,
    *,
    app_env: str,
    mode: str,
) -> None:
    """Prepare schema without granting production runtime code a DDL path."""

    normalized_env = app_env.strip().lower()
    normalized_mode = mode.strip().lower()

    if normalized_mode == "test-create":
        if normalized_env != "test":
            raise RuntimeError(
                "AUTH_STARTUP_SCHEMA_MODE=test-create is allowed only when APP_ENV=test; "
                "refusing runtime schema creation."
            )
        metadata.create_all(bind=engine)
        assert_schema_matches_models(engine, metadata)
        return

    if normalized_mode != "validate":
        raise RuntimeError(
            "AUTH_STARTUP_SCHEMA_MODE must be 'validate' or the test-only 'test-create'."
        )

    assert_alembic_at_head(engine)
    assert_schema_matches_models(engine, metadata, require_all_tables=True)
