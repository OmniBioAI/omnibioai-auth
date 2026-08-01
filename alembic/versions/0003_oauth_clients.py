"""Phase 2 PR1: oauth_clients table (OAuth 2.1 client_credentials grant)

Purely additive -- creates one new table. Nothing existing is altered,
renamed, or dropped; no relationship to api_keys or any other existing
table beyond FKs into organizations/users. Safe to `alembic upgrade head`
on any environment already at 0002_multi_tenant_schema. See
docs/MIGRATIONS.md.

Revision ID: 0003_oauth_clients
Revises: 0002_multi_tenant_schema
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_oauth_clients"
down_revision: Union[str, None] = "0002_multi_tenant_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE_KWARGS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
        **_TABLE_KWARGS,
    )


def downgrade() -> None:
    op.drop_table("oauth_clients")
