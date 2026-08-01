"""Phase 2 PR5: organization_sso_configs break-glass override fields

Purely additive -- adds three nullable columns to organization_sso_configs
(sso_override_at, sso_override_reason, sso_override_by_user_id) so a
global admin can suspend `enforced` for a specific org without touching
its own enforced=true setting. Nothing existing is altered, renamed, or
dropped. Safe to `alembic upgrade head` on any environment already at
0005_org_sso_operational_fields. See docs/MIGRATIONS.md.

Revision ID: 0006_sso_enforcement_override
Revises: 0005_org_sso_operational_fields
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_sso_enforcement_override"
down_revision: Union[str, None] = "0005_org_sso_operational_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("organization_sso_configs") as batch_op:
        batch_op.add_column(sa.Column("sso_override_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("sso_override_reason", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("sso_override_by_user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_org_sso_configs_override_by_user_id", "users", ["sso_override_by_user_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("organization_sso_configs") as batch_op:
        batch_op.drop_constraint("fk_org_sso_configs_override_by_user_id", type_="foreignkey")
        batch_op.drop_column("sso_override_by_user_id")
        batch_op.drop_column("sso_override_reason")
        batch_op.drop_column("sso_override_at")
