"""Add revocable records for ToolServer delegated execution tokens.

Revision ID: 0027_delegated_execution_grants
Revises: 0026_saml_enforcement_override
Create Date: 2026-09-15
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0027_delegated_execution_grants"
down_revision: Union[str, None] = "0026_saml_enforcement_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "delegated_execution_grants",
        sa.Column("delegation_id", sa.String(length=36), primary_key=True),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("audience", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_delegated_execution_grants_client_id", "delegated_execution_grants", ["client_id"])


def downgrade() -> None:
    op.drop_index("ix_delegated_execution_grants_client_id", table_name="delegated_execution_grants")
    op.drop_table("delegated_execution_grants")
