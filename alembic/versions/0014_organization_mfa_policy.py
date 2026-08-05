"""PR11.5.5: organization MFA policy

New table only -- no existing table altered, renamed, or dropped. Safe
to `alembic upgrade head` on any environment already at
0013_mfa_foundation; every existing organization survives the upgrade
with zero policy row (absence of a row means "no policy configured",
not "required=false enforced" -- see
docs/pr11-mfa-org-policy-discovery.md §2).

Mirrors 0004_org_sso_schema.py's own create_table shape:
organization_id foreign-keyed to organizations.id and UNIQUE (one
policy row per org), indexed for lookup.

Revision ID: 0014_organization_mfa_policy
Revises: 0013_mfa_foundation
Create Date: 2026-08-05

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0014_organization_mfa_policy"
down_revision: Union[str, None] = "0013_mfa_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organization_mfa_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("enabled_at", sa.DateTime(), nullable=True),
        sa.Column("enabled_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("override_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("override_reason", sa.String(length=500), nullable=True),
        sa.Column("override_at", sa.DateTime(), nullable=True),
        sa.Column("override_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
    )
    op.create_index(
        "ix_organization_mfa_policies_organization_id",
        "organization_mfa_policies",
        ["organization_id"],
    )


def downgrade() -> None:
    # No explicit drop_index before drop_table -- on MySQL, organization_id's
    # index also backs its FK constraint, and MySQL refuses to drop an
    # index still "needed in a foreign key constraint" even when the
    # whole table is being dropped. drop_table removes the table (and
    # every index on it) in one DDL statement, sidestepping the ordering
    # problem -- same fix 0013_mfa_foundation's own downgrade() already
    # applied for mfa_devices/mfa_recovery_codes, confirmed against a
    # real MySQL server there.
    op.drop_table("organization_mfa_policies")
