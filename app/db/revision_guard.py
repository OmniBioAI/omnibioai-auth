"""Read-only verification that the database is at the bundled Alembic head."""

from pathlib import Path

from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine


class AlembicRevisionError(RuntimeError):
    """Raised when the database migration state is absent, behind, or branched."""


def assert_alembic_at_head(engine: Engine, script_location: str | Path) -> None:
    """Compare the version recorded in the database with this image's sole head.

    This function only performs SELECT/metadata inspection. It never stamps or
    upgrades a database.
    """
    script = ScriptDirectory(str(script_location))
    heads = script.get_heads()
    if len(heads) != 1:
        raise AlembicRevisionError(
            f"Auth release must have exactly one Alembic head; found {heads}."
        )

    inspector = inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        raise AlembicRevisionError(
            "Database has no alembic_version table; apply reviewed migrations before starting Auth."
        )

    with engine.connect() as connection:
        revisions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    if revisions != heads:
        raise AlembicRevisionError(
            f"Database Alembic revision {revisions} does not match Auth release head {heads}; "
            "apply reviewed migrations before starting Auth."
        )
