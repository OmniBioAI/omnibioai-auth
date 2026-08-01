"""Phase 2 PR3: organization_sso_configs operational fields

Purely additive -- adds two nullable columns to organization_sso_configs
(last_verified_at, verification_error) for future enterprise
troubleshooting. Nothing existing is altered, renamed, or dropped. Safe
to `alembic upgrade head` on any environment already at
0004_org_sso_schema. See docs/MIGRATIONS.md.

Revision ID: 0005_org_sso_operational_fields
Revises: 0004_org_sso_schema
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_org_sso_operational_fields"
down_revision: Union[str, None] = "0004_org_sso_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("organization_sso_configs") as batch_op:
        batch_op.add_column(sa.Column("last_verified_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("verification_error", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("organization_sso_configs") as batch_op:
        batch_op.drop_column("verification_error")
        batch_op.drop_column("last_verified_at")
