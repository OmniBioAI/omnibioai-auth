"""Widen api_keys.key_prefix from 12 to 20 characters.

M13 (live/test key prefixes) changed the stored prefix to
prefix_len("omni_sk_live_"/"omni_sk_test_") + 4 display chars = 17
characters, but never widened this column from its pre-M13 size of 12
(sized for the plain "omni_sk_XXXX" scheme). Every real key creation
against a real MySQL database has failed with "Data too long for
column 'key_prefix'" since M13 shipped -- SQLite enforces no VARCHAR
length limit at all, so the existing (SQLite-backed) test suite never
caught this.

Revision ID: 0029_widen_api_key_prefix
Revises: 0028_auth_audit_integrity
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0029_widen_api_key_prefix"
down_revision: Union[str, None] = "0028_auth_audit_integrity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.alter_column(
            "key_prefix", existing_type=sa.String(length=12), type_=sa.String(length=20), existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.alter_column(
            "key_prefix", existing_type=sa.String(length=20), type_=sa.String(length=12), existing_nullable=True,
        )
