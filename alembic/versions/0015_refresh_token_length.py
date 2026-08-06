"""PR12: widen refresh_tokens.token from VARCHAR(500) to VARCHAR(767)

Adding iss/aud claims to every issued token (core/jwt.py::_sign) pushed a
real refresh token past 500 characters -- observed failing in production-
shape MySQL with "Data too long for column 'token'" on login (a plain,
no-org user's token was already ~524 chars; an org-scoped user with
org_role/permissions populated is longer still). 767 is the largest
VARCHAR this column's existing UNIQUE index can hold without exceeding
InnoDB's 3072-byte max index key length at utf8mb4's 4 bytes/char
(767 * 4 = 3068). Purely a length widening -- no data migration needed,
every existing value already fits.

Revision ID: 0015_refresh_token_length
Revises: 0014_organization_mfa_policy
Create Date: 2026-08-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0015_refresh_token_length"
down_revision: Union[str, None] = "0014_organization_mfa_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.alter_column(
            "token",
            existing_type=sa.String(length=500),
            type_=sa.String(length=767),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.alter_column(
            "token",
            existing_type=sa.String(length=767),
            type_=sa.String(length=500),
            existing_nullable=True,
        )
