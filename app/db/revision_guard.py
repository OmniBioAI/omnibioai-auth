"""Fail-closed startup validation for the Auth Alembic revision."""

from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Engine


class AlembicRevisionError(RuntimeError):
    """Raised when the connected database is not at every Alembic head."""


def _expected_heads() -> tuple[str, ...]:
    repo_root = Path(__file__).resolve().parents[2]
    config = Config(str(repo_root / "alembic.ini"))
    config.set_main_option("script_location", str(repo_root / "alembic"))
    return tuple(sorted(ScriptDirectory.from_config(config).get_heads()))


def assert_alembic_at_head(engine: Engine) -> None:
    """Require the database's recorded revision set to equal code's heads.

    This performs metadata reads only. Missing version bookkeeping, an empty
    version table, multiple/unexpected revisions, and a database behind or
    ahead of this checkout all refuse startup before bootstrap DML begins.
    """

    expected = _expected_heads()
    try:
        with engine.connect() as connection:
            current = tuple(sorted(MigrationContext.configure(connection).get_current_heads()))
    except Exception as exc:
        raise AlembicRevisionError(
            "Unable to read Alembic revision state with the Auth runtime "
            "database principal; refusing startup."
        ) from exc

    if current != expected:
        recorded = ", ".join(current) if current else "<none>"
        required = ", ".join(expected) if expected else "<no code heads>"
        raise AlembicRevisionError(
            "Auth database revision mismatch: recorded "
            f"[{recorded}], required [{required}]. Refusing startup. Apply "
            "reviewed migrations separately with the migration principal, "
            "then restart Auth."
        )
