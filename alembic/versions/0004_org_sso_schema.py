"""Phase 2 PR2: organization_sso_configs table + oauth_accounts widen

Purely additive/widening -- creates one new table and adds one nullable
column to oauth_accounts, whose 2-column unique constraint is replaced
with a 3-column constraint that every existing row still satisfies
unchanged (every existing row has organization_sso_config_id = NULL, and
MySQL treats each NULL as distinct across a composite unique index).
Nothing existing is altered in value, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at 0003_oauth_clients.
See docs/MIGRATIONS.md.

Revision ID: 0004_org_sso_schema
Revises: 0003_oauth_clients
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_org_sso_schema"
down_revision: Union[str, None] = "0003_oauth_clients"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE_KWARGS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

_OAUTH_ACCOUNTS_OLD_UQ = "uq_oauth_provider_account"
_OAUTH_ACCOUNTS_SSO_FK = "fk_oauth_accounts_organization_sso_config_id"


def upgrade() -> None:
    op.create_table(
        "organization_sso_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider_type", sa.String(length=20), nullable=True),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret_encrypted", sa.String(length=1000), nullable=False),
        sa.Column("authorization_endpoint", sa.String(length=500), nullable=True),
        sa.Column("token_endpoint", sa.String(length=500), nullable=True),
        sa.Column("userinfo_endpoint", sa.String(length=500), nullable=True),
        sa.Column("jwks_uri", sa.String(length=500), nullable=True),
        sa.Column("allowed_domains", sa.JSON(), nullable=True),
        sa.Column("enforced", sa.Boolean(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.UniqueConstraint("organization_id", name="uq_organization_sso_configs_org"),
        **_TABLE_KWARGS,
    )

    # batch_alter_table so this applies cleanly on both MySQL (plain ALTER
    # TABLE) and SQLite (table-recreation under the hood) -- required for
    # the SQLite leg of tests/test_migrations.py to exercise the exact
    # same migration code path as the MySQL leg. The constraint drop+add
    # happens inside this one batch operation (one transactional DDL
    # step), not as separate manual commands -- see this revision's entry
    # in docs/MIGRATIONS.md for why that sequencing matters.
    with op.batch_alter_table("oauth_accounts") as batch_op:
        batch_op.add_column(sa.Column("organization_sso_config_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            _OAUTH_ACCOUNTS_SSO_FK, "organization_sso_configs", ["organization_sso_config_id"], ["id"]
        )
        batch_op.drop_constraint(_OAUTH_ACCOUNTS_OLD_UQ, type_="unique")
        batch_op.create_unique_constraint(
            _OAUTH_ACCOUNTS_OLD_UQ,
            ["provider", "provider_user_id", "organization_sso_config_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("oauth_accounts") as batch_op:
        batch_op.drop_constraint(_OAUTH_ACCOUNTS_OLD_UQ, type_="unique")
        batch_op.create_unique_constraint(
            _OAUTH_ACCOUNTS_OLD_UQ, ["provider", "provider_user_id"]
        )
        batch_op.drop_constraint(_OAUTH_ACCOUNTS_SSO_FK, type_="foreignkey")
        batch_op.drop_column("organization_sso_config_id")

    op.drop_table("organization_sso_configs")
