"""SAML PR11: Single Logout (SLO) support columns

Purely additive -- two nullable columns on `organization_saml_configs`
and three nullable columns on `sessions`. No existing column, index, or
constraint is touched.

`organization_saml_configs.slo_url`: the IdP's SingleLogoutService
endpoint. Genuinely distinct from the existing `sso_url` column --
verified by reading python3-saml's own settings.py directly:
idp.singleLogoutService.url is a separate settings key from
idp.singleSignOnService.url, and get_idp_slo_url() returns None (not
sso_url) when it's unset. Nullable: an org's SAML config can support
login without its IdP also supporting SLO.

`sessions.saml_name_id` / `sessions.saml_session_index` /
`sessions.organization_saml_config_id`: what an IdP-initiated
LogoutRequest actually carries (NameID + SessionIndex, never this
session's own refresh-token family_id) to identify which local
session(s) to revoke. Nothing in this schema persisted that mapping
before PR11 -- SAMLIdentity.session_index (PR5) was extracted at ACS
time but discarded once tokens were issued. All three nullable and only
ever populated for a SAML-originated session; every password/OAuth/
OIDC-SSO/license session, and every session that predates this
migration, has NULL in all three.

Revision ID: 0023_saml_slo
Revises: 0022_oauth_saml_config_id
Create Date: 2026-08-12

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0023_saml_slo"
down_revision: Union[str, None] = "0022_oauth_saml_config_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SESSIONS_SAML_CONFIG_FK = "fk_sessions_organization_saml_config_id"


def upgrade() -> None:
    # batch_alter_table so this applies cleanly on both MySQL (plain ALTER
    # TABLE) and SQLite (table-recreation under the hood) -- same
    # convention 0022_oauth_saml_config_id already established, required
    # for tests/test_migrations.py's SQLite leg to exercise the same code
    # path as the MySQL leg.
    with op.batch_alter_table("organization_saml_configs") as batch_op:
        batch_op.add_column(sa.Column("slo_url", sa.String(500), nullable=True))

    with op.batch_alter_table("sessions") as batch_op:
        batch_op.add_column(sa.Column("saml_name_id", sa.String(500), nullable=True))
        batch_op.add_column(sa.Column("saml_session_index", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("organization_saml_config_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_sessions_saml_name_id", ["saml_name_id"])
        batch_op.create_foreign_key(
            _SESSIONS_SAML_CONFIG_FK, "organization_saml_configs", ["organization_saml_config_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("sessions") as batch_op:
        batch_op.drop_constraint(_SESSIONS_SAML_CONFIG_FK, type_="foreignkey")
        batch_op.drop_index("ix_sessions_saml_name_id")
        batch_op.drop_column("organization_saml_config_id")
        batch_op.drop_column("saml_session_index")
        batch_op.drop_column("saml_name_id")

    with op.batch_alter_table("organization_saml_configs") as batch_op:
        batch_op.drop_column("slo_url")
