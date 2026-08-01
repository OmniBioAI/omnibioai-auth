"""Phase 3 PR2: organization status change tracking

Purely additive -- adds three nullable columns to organizations
(status_changed_at, status_changed_reason, status_changed_by_user_id) so
a platform admin's suspend/reactivate action (app/api/routes_orgs.py's
PATCH /orgs/{org_id}) records who/why/when, mirroring the exact pattern
Phase 2 PR5 established for organization_sso_configs' break-glass
override. An explicit extension point for Phase 3 PR4's audit pipeline,
not a replacement for it -- see org_service.update_organization. Nothing
existing is altered, renamed, or dropped. Safe to `alembic upgrade head`
on any environment already at 0007_refresh_token_rotation.

Revision ID: 0008_org_status_tracking
Revises: 0007_refresh_token_rotation
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_org_status_tracking"
down_revision: Union[str, None] = "0007_refresh_token_rotation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.add_column(sa.Column("status_changed_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("status_changed_reason", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("status_changed_by_user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_organizations_status_changed_by_user_id", "users", ["status_changed_by_user_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("organizations") as batch_op:
        batch_op.drop_constraint("fk_organizations_status_changed_by_user_id", type_="foreignkey")
        batch_op.drop_column("status_changed_by_user_id")
        batch_op.drop_column("status_changed_reason")
        batch_op.drop_column("status_changed_at")
