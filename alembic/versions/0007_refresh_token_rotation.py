"""Phase 3 PR0.2: refresh_tokens rotation + reuse-detection fields

Purely additive -- adds two nullable columns to refresh_tokens (family_id,
rotated_at) so /auth/refresh can rotate the refresh token on every use and
detect replay of an already-rotated token (revoking the whole family on
reuse). Every existing row gets NULL for both and is treated as a
single-member family the first time it's used post-migration -- nothing
existing is altered, renamed, or dropped. Safe to `alembic upgrade head` on
any environment already at 0006_sso_enforcement_override. See
docs/MIGRATIONS.md.

Revision ID: 0007_refresh_token_rotation
Revises: 0006_sso_enforcement_override
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_refresh_token_rotation"
down_revision: Union[str, None] = "0006_sso_enforcement_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.add_column(sa.Column("family_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("rotated_at", sa.DateTime(), nullable=True))
        batch_op.create_index("ix_refresh_tokens_family_id", ["family_id"])


def downgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch_op:
        batch_op.drop_index("ix_refresh_tokens_family_id")
        batch_op.drop_column("rotated_at")
        batch_op.drop_column("family_id")
