"""multi-tenant schema: organizations, teams, memberships, api keys

Purely additive -- creates 7 new tables and adds 3 nullable columns to
license_keys. Nothing existing is altered, renamed, or dropped. No ORM model
classes exist for the new tables yet (deferred to a later change); this
revision only creates the schema. Safe to `alembic upgrade head` on any
environment already stamped at 0001_baseline. See docs/MIGRATIONS.md.

Revision ID: 0002_multi_tenant_schema
Revises: 0001_baseline
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_multi_tenant_schema"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE_KWARGS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

_LICENSE_KEYS_ORG_FK = "fk_license_keys_organization_id"


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("plan", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("organization_id", "name", name="uq_teams_org_name"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("invited_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("joined_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_memberships_org_user"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "membership_roles",
        sa.Column(
            "membership_id", sa.Integer(),
            sa.ForeignKey("organization_memberships.id"), nullable=False,
        ),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id"), nullable=False),
        sa.PrimaryKeyConstraint("membership_id", "role_id", name="pk_membership_roles"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "team_memberships",
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.PrimaryKeyConstraint("team_id", "user_id", name="pk_team_memberships"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("key_prefix", sa.String(length=12), nullable=True),
        sa.Column("key_hash", sa.String(length=64), nullable=True),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
        **_TABLE_KWARGS,
    )

    op.create_table(
        "organization_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("llm_provider", sa.String(length=50), nullable=True),
        sa.Column("llm_api_key_encrypted", sa.String(length=1000), nullable=True),
        sa.Column("cloud_provider", sa.String(length=50), nullable=True),
        sa.Column("cloud_credentials_encrypted", sa.String(length=4000), nullable=True),
        sa.Column("work_directory", sa.String(length=500), nullable=True),
        sa.Column("data_directory", sa.String(length=500), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.UniqueConstraint("organization_id", name="uq_organization_config_org"),
        **_TABLE_KWARGS,
    )

    # batch_alter_table so this applies cleanly on both MySQL (plain ALTER
    # TABLE) and SQLite (which needs table-recreation under the hood for
    # some ALTER operations) -- required for the SQLite leg of
    # tests/test_migrations.py to exercise the exact same migration code
    # path as the MySQL leg.
    with op.batch_alter_table("license_keys") as batch_op:
        batch_op.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("machine_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("max_devices", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            _LICENSE_KEYS_ORG_FK, "organizations", ["organization_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("license_keys") as batch_op:
        batch_op.drop_constraint(_LICENSE_KEYS_ORG_FK, type_="foreignkey")
        batch_op.drop_column("max_devices")
        batch_op.drop_column("machine_id")
        batch_op.drop_column("organization_id")

    op.drop_table("organization_config")
    op.drop_table("api_keys")
    op.drop_table("team_memberships")
    op.drop_table("membership_roles")
    op.drop_table("organization_memberships")
    op.drop_table("teams")
    op.drop_table("organizations")
