"""SAML PR6: oauth_accounts.organization_saml_config_id

Purely additive -- adds one nullable column to `oauth_accounts` (a
ForeignKey to `organization_saml_configs`, created by 0021) plus a NEW,
SEPARATE unique constraint scoped to it. Does not touch or widen the
existing `uq_oauth_provider_account` constraint at all.

That's a deliberate departure from 0004_org_sso_schema's own precedent
(which widened its constraint in place to add organization_sso_config_id).
Widening the *same* constraint here instead would add a 4th column that is
NULL on every existing OIDC/3-provider row -- and empirically (verified
against both SQLite and MySQL), a composite UNIQUE index in which *any*
column is NULL for a given row is excluded from uniqueness enforcement
entirely for that row's whole tuple, not just the NULL column. Every
existing OIDC row already has organization_saml_config_id NULL (it's a
brand new column), so widening in place would silently stop rejecting
duplicate (provider, provider_user_id, organization_sso_config_id) rows
for every one of them -- reintroducing the exact cross-tenant `sub`-
collision bug that constraint exists to prevent, the moment any SAML row
exists anywhere in the same table. A second, independent constraint
(`uq_oauth_provider_saml_account`, scoped to organization_saml_config_id
instead) has no such interaction: its own 3 columns are never NULL for a
real SAML row, so it enforces SAML NameID uniqueness per org/config
correctly while leaving the original OIDC/3-provider constraint completely
untouched.

Revision ID: 0022_oauth_saml_config_id
Revises: 0021_organization_saml_config
Create Date: 2026-08-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0022_oauth_saml_config_id"
down_revision: Union[str, None] = "0021_organization_saml_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OAUTH_ACCOUNTS_SAML_UQ = "uq_oauth_provider_saml_account"
_OAUTH_ACCOUNTS_SAML_FK = "fk_oauth_accounts_organization_saml_config_id"


def upgrade() -> None:
    # batch_alter_table so this applies cleanly on both MySQL (plain ALTER
    # TABLE) and SQLite (table-recreation under the hood) -- required for
    # the SQLite leg of tests/test_migrations.py to exercise the exact same
    # migration code path as the MySQL leg.
    with op.batch_alter_table("oauth_accounts") as batch_op:
        batch_op.add_column(sa.Column("organization_saml_config_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            _OAUTH_ACCOUNTS_SAML_FK, "organization_saml_configs", ["organization_saml_config_id"], ["id"]
        )
        batch_op.create_unique_constraint(
            _OAUTH_ACCOUNTS_SAML_UQ,
            ["provider", "provider_user_id", "organization_saml_config_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("oauth_accounts") as batch_op:
        batch_op.drop_constraint(_OAUTH_ACCOUNTS_SAML_UQ, type_="unique")
        batch_op.drop_constraint(_OAUTH_ACCOUNTS_SAML_FK, type_="foreignkey")
        batch_op.drop_column("organization_saml_config_id")
