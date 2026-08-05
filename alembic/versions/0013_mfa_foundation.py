"""PR11.5.1: MFA database foundation

Schema only -- no login flow, challenge, or enforcement logic changes.
See docs/pr11-mfa-database-foundation-discovery.md for the full design.

Adds 5 status-metadata columns to `users` (mirrors 0012's own
batch_alter_table approach for SQLite compatibility): `mfa_enabled`
(NOT NULL DEFAULT false -- a live current-state flag, not a historical
fact, so unlike this migration's nullable siblings it gets a real
default rather than a no-backfill NULL: every pre-existing row is
unambiguously "MFA not enabled" today), `mfa_status` (NOT NULL DEFAULT
"disabled"), and three nullable historical fields
(`mfa_primary_method`, `mfa_enabled_at`, `mfa_last_verified_at`) with
no backfill, following 0009/0012's own "existing rows have no history
to invent" convention.

Creates two brand-new tables, `mfa_devices` and `mfa_recovery_codes`
(mirrors 0011_audit_events.py's create_table shape), both FK'd and
indexed on user_id to support multiple factors per user in the future.
No existing table's constraints, indexes, or data are altered.

Existing users continue authenticating exactly as before: nothing in
this migration is read by any login path yet (that starts at
PR11.5.3, per docs/pr11-security-foundation-discovery.md's roadmap in
omnibioai-control-center). Safe to `alembic upgrade head` on any
environment already at 0012_user_login_metadata.

Revision ID: 0013_mfa_foundation
Revises: 0012_user_login_metadata
Create Date: 2026-08-04

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0013_mfa_foundation"
down_revision: Union[str, None] = "0012_user_login_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(
            sa.Column("mfa_status", sa.String(length=20), nullable=False, server_default="disabled")
        )
        batch_op.add_column(sa.Column("mfa_primary_method", sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column("mfa_enabled_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("mfa_last_verified_at", sa.DateTime(), nullable=True))

    op.create_table(
        "mfa_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("device_type", sa.String(length=20), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("encrypted_secret", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_mfa_devices_user_id", "mfa_devices", ["user_id"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"])


def downgrade() -> None:
    # No explicit drop_index before drop_table: on MySQL, user_id's index
    # also backs its FK constraint, and MySQL refuses to drop an index
    # still "needed in a foreign key constraint" even when the whole
    # table is being dropped in the same statement sequence. drop_table
    # removes the table (and every index on it, FK-backing or not) in
    # one DDL statement, sidestepping the ordering problem entirely --
    # confirmed against a real MySQL server, not just SQLite (which
    # never raised this error to begin with).
    op.drop_table("mfa_recovery_codes")
    op.drop_table("mfa_devices")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_last_verified_at")
        batch_op.drop_column("mfa_enabled_at")
        batch_op.drop_column("mfa_primary_method")
        batch_op.drop_column("mfa_status")
        batch_op.drop_column("mfa_enabled")
