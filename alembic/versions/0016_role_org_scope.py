"""PR13: roles.organization_id for tenant-isolated custom roles

Adds a nullable organization_id FK to `roles`. NULL means a platform-wide
role (admin, platform_admin, org_admin, org_member, user, scientist,
viewer) -- every existing row gets NULL for free, no backfill needed, and
every existing call site (which never passes organization_id) keeps
creating platform-wide roles unchanged. Non-NULL means a custom role
owned by that organization, invisible to every other org.

Also drops the pre-existing global UNIQUE constraint on roles.name
(named "name" in 0001_baseline.py). MySQL treats each NULL as distinct in
a unique index, so a straightforward composite UNIQUE(organization_id,
name) would not actually prevent two different platform-wide roles (both
organization_id=NULL) from sharing a name -- it would silently allow
exactly the collision it's meant to prevent. Uniqueness-within-scope is
instead enforced in app/services/role_service.py, consistent with this
repo's existing convention of app-level validation for business rules
(_validate_permission_names, the self-escalation guards) rather than
encoding them in the schema. The dropped unique constraint is replaced
with a plain non-unique index for lookup performance.

Revision ID: 0016_role_org_scope
Revises: 0015_refresh_token_length
Create Date: 2026-08-06

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0016_role_org_scope"
down_revision: Union[str, None] = "0015_refresh_token_length"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("roles") as batch_op:
        batch_op.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_roles_organization_id", "organizations", ["organization_id"], ["id"]
        )
        batch_op.create_index("ix_roles_organization_id", ["organization_id"])
        batch_op.drop_constraint("name", type_="unique")
        batch_op.create_index("ix_roles_name", ["name"])


def downgrade() -> None:
    with op.batch_alter_table("roles") as batch_op:
        batch_op.drop_index("ix_roles_name")
        batch_op.create_unique_constraint("name", ["name"])
        # FK constraint must be dropped before the index backing it --
        # MySQL refuses to drop an index still "needed in a foreign key
        # constraint" (errno 1553).
        batch_op.drop_constraint("fk_roles_organization_id", type_="foreignkey")
        batch_op.drop_index("ix_roles_organization_id")
        batch_op.drop_column("organization_id")
