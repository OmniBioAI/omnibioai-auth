"""#263: per-org SAML enforcement -- organization_saml_configs gains
enforced + allowed_domains

Purely additive -- adds two nullable columns to organization_saml_configs,
mirroring organization_sso_configs' own enforced/allowed_domains columns
(0004_org_sso_schema) exactly, including the same nullable-at-the-DB-
level-with-only-an-ORM-default shape. Nothing existing is altered,
renamed, or dropped. Safe to `alembic upgrade head` on any environment
already at 0024_mfa_totp_replay_protection. See docs/MIGRATIONS.md.

allowed_domains is a genuinely new capability for SAML (OrganizationSAMLConfig
had no domain-to-org lookup mechanism at all before this) -- required for
find_enforced_saml_org_for_email to resolve which org's SAML config
applies to a login attempt's email domain, the same way
find_enforced_org_for_email already does for OIDC via
OrganizationSSOConfig.allowed_domains.

Revision ID: 0025_saml_enforcement
Revises: 0024_mfa_totp_replay_protection
Create Date: 2026-08-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0025_saml_enforcement"
down_revision: Union[str, None] = "0024_mfa_totp_replay_protection"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("organization_saml_configs") as batch_op:
        batch_op.add_column(sa.Column("allowed_domains", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("enforced", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("organization_saml_configs") as batch_op:
        batch_op.drop_column("enforced")
        batch_op.drop_column("allowed_domains")
