"""Phase 3 PR3B: role description field

Purely additive -- adds a nullable `description` column to `roles`, needed
for the new platform-admin/org-admin role management UI's RoleSummary
response (id/name/description/permissions). Existing rows get NULL until
an operator sets one via the (also extended by this PR) role CRUD
endpoints; nothing existing is altered, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at
0009_user_directory_fields.

Deliberately NOT extending this to `user_roles`/`membership_roles` for
assignment metadata (who/when assigned a role) -- those are bare
many-to-many association tables with no per-row extra columns today, and
every existing call site mutates them via the ORM's collection API
(`user.roles.append(role)`, `membership.roles = [...]`), which cannot
populate extra association columns without being rewritten to issue
explicit INSERTs instead. That is a materially larger, riskier change
than this PR's stated scope ("reuse the existing permission system, do
not redesign RBAC") justifies -- see this PR's implementation report for
the full reasoning. `roles`, by contrast, is already a normal mapped
entity; adding one nullable column to it carries none of that risk.

Revision ID: 0010_role_description
Revises: 0009_user_directory_fields
Create Date: 2026-08-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0010_role_description"
down_revision: Union[str, None] = "0009_user_directory_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("roles") as batch_op:
        batch_op.add_column(sa.Column("description", sa.String(length=500), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("roles") as batch_op:
        batch_op.drop_column("description")
