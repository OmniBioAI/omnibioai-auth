"""Production schema validation must be read-only and fail closed."""

from pathlib import Path

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import Column, Integer, MetaData, Table, create_engine, inspect, text

from app.db.revision_guard import AlembicRevisionError
from app.db.startup_schema import StartupSchemaError, prepare_startup_schema


ALEMBIC = Path(__file__).resolve().parents[1] / "alembic"
HEAD = ScriptDirectory(str(ALEMBIC)).get_current_head()


def _engine_with_revision(revision: str | None):
    engine = create_engine("sqlite://")
    metadata = MetaData()
    Table("sample", metadata, Column("id", Integer, primary_key=True))
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        if revision is not None:
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )
    return engine, metadata


def test_validate_accepts_exact_release_head_without_schema_writes():
    engine, metadata = _engine_with_revision(HEAD)
    before = set(inspect(engine).get_table_names())

    prepare_startup_schema(
        engine, metadata, app_env="production", mode="validate", script_location=ALEMBIC
    )

    after = set(inspect(engine).get_table_names())
    assert after == before


@pytest.mark.parametrize("revision", [None, "0030_user_timezone"])
def test_validate_rejects_missing_or_stale_revision(revision):
    engine, metadata = _engine_with_revision(revision)
    with pytest.raises(AlembicRevisionError):
        prepare_startup_schema(
            engine, metadata, app_env="production", mode="validate", script_location=ALEMBIC
        )


def test_test_create_mode_is_refused_outside_test_environment():
    engine, metadata = _engine_with_revision(HEAD)
    with pytest.raises(StartupSchemaError, match="only when APP_ENV=test"):
        prepare_startup_schema(
            engine, metadata, app_env="production", mode="test-create", script_location=ALEMBIC
        )


def test_validate_rejects_missing_application_table():
    engine = create_engine("sqlite://")
    metadata = MetaData()
    Table("sample", metadata, Column("id", Integer, primary_key=True))
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": HEAD},
        )
    with pytest.raises(StartupSchemaError, match="missing Auth tables"):
        prepare_startup_schema(
            engine, metadata, app_env="production", mode="validate", script_location=ALEMBIC
        )
