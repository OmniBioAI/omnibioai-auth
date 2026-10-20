from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Column, Integer, MetaData, Table, create_engine, text

from app.db.revision_guard import AlembicRevisionError, assert_alembic_at_head
from app.db.schema_guard import SchemaDriftError
from app.db.startup_schema import prepare_startup_schema


def _head() -> str:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert len(heads) == 1
    return heads[0]


def _versioned_engine(revision: str | None):
    engine = create_engine("sqlite://")
    if revision is not None:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(255) NOT NULL)"))
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": revision},
            )
    return engine


def test_revision_guard_accepts_exact_code_head():
    assert_alembic_at_head(_versioned_engine(_head()))


@pytest.mark.parametrize("revision", [None, "unexpected_revision"])
def test_revision_guard_fails_closed_for_missing_or_mismatched_revision(revision):
    with pytest.raises(AlembicRevisionError, match="refusing startup|Refusing startup"):
        assert_alembic_at_head(_versioned_engine(revision))


def test_validate_mode_performs_no_schema_creation():
    engine = _versioned_engine(_head())
    metadata = MetaData()
    Table("would_require_ddl", metadata, Column("id", Integer, primary_key=True))

    with pytest.raises(SchemaDriftError, match="missing tables"):
        prepare_startup_schema(engine, metadata, app_env="production", mode="validate")

    with engine.connect() as connection:
        names = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).scalars()
        assert "would_require_ddl" not in set(names)


def test_test_create_mode_is_rejected_outside_test_environment():
    metadata = MetaData()
    Table("forbidden_runtime_ddl", metadata, Column("id", Integer, primary_key=True))
    with pytest.raises(RuntimeError, match="allowed only when APP_ENV=test"):
        prepare_startup_schema(
            create_engine("sqlite://"),
            metadata,
            app_env="production",
            mode="test-create",
        )
