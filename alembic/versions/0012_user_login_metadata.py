"""PR11.1: user login metadata

Purely additive -- adds `last_login_at` and `authentication_method` to
`users`, mirroring 0009_user_directory_fields' own approach (nullable,
no backfill: existing rows have no login history to invent). Written by
exactly one code path, auth_service.generate_tokens, on every successful
login (password/oauth/sso/license) -- never by /auth/refresh, which
continues a session rather than starting one. Nothing existing is
altered, renamed, or dropped. Safe to `alembic upgrade head` on any
environment already at 0011_audit_events.

Revision ID: 0012_user_login_metadata
Revises: 0011_audit_events
Create Date: 2026-08-04

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0012_user_login_metadata"
down_revision: Union[str, None] = "0011_audit_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("authentication_method", sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("authentication_method")
        batch_op.drop_column("last_login_at")
