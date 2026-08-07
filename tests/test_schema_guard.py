"""Unit coverage for app/db/schema_guard.py -- the startup fail-fast check
added after the 2026-08-06 incident where `Base.metadata.create_all()`
silently did nothing against a `roles` table that predated
`0016_role_org_scope`, and the first bootstrap query to reference
`roles.organization_id` crashed with a raw OperationalError instead of a
clear, actionable message. See docs/MIGRATIONS.md 'Known risk: create_all()
vs. Alembic drift'.
"""

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine

from app.db.schema_guard import SchemaDriftError, assert_schema_matches_models


@pytest.fixture
def engine(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'schema_guard.db'}"
    return create_engine(db_url)


def test_passes_when_live_schema_matches_metadata(engine):
    metadata = MetaData()
    Table("widgets", metadata, Column("id", Integer, primary_key=True), Column("name", String(50)))
    metadata.create_all(bind=engine)

    assert_schema_matches_models(engine, metadata)  # must not raise


def test_raises_when_an_existing_table_is_missing_a_column(engine):
    # Simulate a table created before a column existed on its ORM class --
    # exactly what create_all() leaves behind for any pre-existing table.
    old_metadata = MetaData()
    Table("widgets", old_metadata, Column("id", Integer, primary_key=True))
    old_metadata.create_all(bind=engine)

    new_metadata = MetaData()
    Table("widgets", new_metadata, Column("id", Integer, primary_key=True), Column("name", String(50)))

    with pytest.raises(SchemaDriftError, match="widgets"):
        assert_schema_matches_models(engine, new_metadata)


def test_error_message_names_the_missing_column_and_points_at_the_fix(engine):
    old_metadata = MetaData()
    Table("roles", old_metadata, Column("id", Integer, primary_key=True))
    old_metadata.create_all(bind=engine)

    new_metadata = MetaData()
    Table(
        "roles",
        new_metadata,
        Column("id", Integer, primary_key=True),
        Column("organization_id", Integer),
    )

    with pytest.raises(SchemaDriftError) as exc_info:
        assert_schema_matches_models(engine, new_metadata)

    message = str(exc_info.value)
    assert "roles" in message
    assert "organization_id" in message
    assert "alembic upgrade head" in message


def test_does_not_flag_a_table_that_does_not_exist_at_all(engine):
    # A table create_all() (or a pending migration) hasn't created yet is
    # not this guard's concern -- only existing-but-stale tables are.
    metadata = MetaData()
    Table("ghost", metadata, Column("id", Integer, primary_key=True))

    assert_schema_matches_models(engine, metadata)  # must not raise


def test_reports_every_drifted_table_in_one_pass(engine):
    old_metadata = MetaData()
    Table("widgets", old_metadata, Column("id", Integer, primary_key=True))
    Table("gadgets", old_metadata, Column("id", Integer, primary_key=True))
    old_metadata.create_all(bind=engine)

    new_metadata = MetaData()
    Table("widgets", new_metadata, Column("id", Integer, primary_key=True), Column("name", String(50)))
    Table("gadgets", new_metadata, Column("id", Integer, primary_key=True), Column("label", String(50)))

    with pytest.raises(SchemaDriftError) as exc_info:
        assert_schema_matches_models(engine, new_metadata)

    message = str(exc_info.value)
    assert "widgets" in message
    assert "gadgets" in message
