"""Phase 3 PR3A: user directory fields

Purely additive -- adds `created_at` (needed for the new platform-admin
user directory's "Created"/sort-by-created_at column, which `users` had
no equivalent of at all) and status-change tracking
(status_changed_at/reason/by_user_id) to `users`, mirroring
`organizations`' own status-tracking columns from 0008 exactly, which
itself mirrored organization_sso_configs' break-glass override columns
from 0006. Nothing existing is altered, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at
0008_org_status_tracking.

Revision ID: 0009_user_directory_fields
Revises: 0008_org_status_tracking
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009_user_directory_fields"
down_revision: Union[str, None] = "0008_org_status_tracking"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("created_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("status_changed_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("status_changed_reason", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("status_changed_by_user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_users_status_changed_by_user_id", "users", ["status_changed_by_user_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("fk_users_status_changed_by_user_id", type_="foreignkey")
        batch_op.drop_column("status_changed_by_user_id")
        batch_op.drop_column("status_changed_reason")
        batch_op.drop_column("status_changed_at")
        batch_op.drop_column("created_at")
