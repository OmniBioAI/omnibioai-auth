"""Stop indexing refresh_tokens.token; add a hashed lookup column instead

0015 already widened refresh_tokens.token from VARCHAR(500) to VARCHAR(767)
once for exactly this reason (PR12's iss/aud claims pushed a real token
past 500 chars). It just happened again: granting a user an additional
role widens the JWT's `permissions` claim, and once a token's encoded
length exceeds 767 chars, login itself starts failing outright with
"Data too long for column 'token'" -- there is no VARCHAR length that's
safe forever as long as the raw JWT is what's indexed, since InnoDB caps
an indexed utf8mb4 VARCHAR at 767 chars (3072-byte max key length / 4
bytes per char).

Fix: index a fixed-width SHA-256 hex digest (token_hash, 64 chars)
instead of the raw token. `token` itself is widened to TEXT -- no longer
indexed, so no length ceiling applies to it at all -- and kept only for
reference; every lookup (app/services/auth_service.py's revoke_token/
rotate_refresh_token) now filters on token_hash instead.

Existing rows are backfilled via MySQL's own SHA2(token, 256), which
matches Python's hashlib.sha256(...).hexdigest() byte-for-byte, so this
needs no application code running mid-migration. SQLite has no SHA2
builtin at all (see the dialect check in upgrade() below) -- this repo's
own test suite runs its SQLite migration coverage against exactly this
revision (tests/test_migrations.py), so a fresh test database must be
able to reach `head` too, not only a real MySQL deployment; the Python
fallback below produces the identical digest for the same input.

Revision ID: 0017_refresh_token_hash
Revises: 0016_role_org_scope
Create Date: 2026-08-08

"""
import hashlib
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0017_refresh_token_hash"
down_revision: Union[str, None] = "0016_role_org_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.add_column(sa.Column("token_hash", sa.String(length=64), nullable=True))

    # Backfill before the column is made unique-indexed below, so the
    # index build itself never has to contend with NULLs from rows that
    # predate this migration. MySQL's SHA2() does this in one statement;
    # every other dialect (SQLite in particular -- see module docstring)
    # has no equivalent builtin function, so fall back to a row-by-row
    # Python hash there instead. Either path writes the same digest.
    bind = op.get_bind()
    if bind.dialect.name == "mysql":
        op.execute("UPDATE refresh_tokens SET token_hash = SHA2(token, 256) WHERE token IS NOT NULL")
    else:
        refresh_tokens = sa.table(
            "refresh_tokens",
            sa.column("id", sa.Integer),
            sa.column("token", sa.Text),
            sa.column("token_hash", sa.String),
        )
        rows = bind.execute(
            sa.select(refresh_tokens.c.id, refresh_tokens.c.token).where(
                refresh_tokens.c.token.isnot(None)
            )
        ).fetchall()
        for row_id, token in rows:
            bind.execute(
                refresh_tokens.update()
                .where(refresh_tokens.c.id == row_id)
                .values(token_hash=hashlib.sha256(token.encode()).hexdigest())
            )

    with op.batch_alter_table("refresh_tokens") as batch_op:
        # 0001_baseline declared this as a named UniqueConstraint, not an
        # Index (`sa.UniqueConstraint("token", name="ix_refresh_tokens_token")`)
        # -- `drop_constraint(type_="unique")` is the operation that
        # actually matches that object on every dialect this repo
        # supports; `drop_index` only ever matches a true `sa.Index`,
        # which SQLite (unlike MySQL) never materializes for a
        # constraint declared this way, and raises "no such index" here.
        batch_op.drop_constraint("ix_refresh_tokens_token", type_="unique")
        batch_op.alter_column(
            "token",
            existing_type=sa.String(length=767),
            type_=sa.Text(),
            existing_nullable=True,
        )
        batch_op.create_index("ix_refresh_tokens_token_hash", ["token_hash"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.drop_index("ix_refresh_tokens_token_hash")
        batch_op.alter_column(
            "token",
            existing_type=sa.Text(),
            type_=sa.String(length=767),
            existing_nullable=True,
        )
        batch_op.create_index("ix_refresh_tokens_token", ["token"], unique=True)
        batch_op.drop_column("token_hash")
