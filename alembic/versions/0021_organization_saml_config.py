"""SAML SSO PR2: organization_saml_configs table

Purely additive -- creates one new table only. Nothing existing is
altered, renamed, or dropped; no other table gains a column (see this
revision's own PR notes: OAuthAccount is deliberately left untouched
until a later PR actually needs a provider="saml" linking column). Safe
to `alembic upgrade head` on any environment already at
0020_team_member_roles.

Mirrors 0004_org_sso_schema.py's organization_sso_configs create_table
shape: organization_id foreign-keyed to organizations.id and UNIQUE (one
SAML IdP configuration per org), same _TABLE_KWARGS convention. No SP
metadata/login/ACS/SLO endpoint exists yet -- this table is unused until
later PRs in the SAML roadmap (PR3 onward) start reading and writing it.

Revision ID: 0021_organization_saml_config
Revises: 0020_team_member_roles
Create Date: 2026-08-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0021_organization_saml_config"
down_revision: Union[str, None] = "0020_team_member_roles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE_KWARGS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}


def upgrade() -> None:
    op.create_table(
        "organization_saml_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("entity_id", sa.String(length=500), nullable=False),
        sa.Column("sso_url", sa.String(length=500), nullable=False),
        sa.Column("x509_certificate", sa.Text(), nullable=False),
        sa.Column("attribute_mapping", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.UniqueConstraint("organization_id", name="uq_organization_saml_configs_org"),
        **_TABLE_KWARGS,
    )


def downgrade() -> None:
    op.drop_table("organization_saml_configs")
