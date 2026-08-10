"""Team Management v0.8.0 Step 1: team ownership + per-member roles

Purely additive -- adds `description` and `created_by_user_id` to `teams`,
and `role`, `invited_by_user_id`, `joined_at` to `team_memberships`. No
existing table is dropped or renamed; no existing column changes type or
is removed.

`team_memberships` was, until now, a plain association table backing only
`Team.members`'s `secondary=` relationship (a flat "is this user on this
team, yes/no" set) -- it carried no data of its own. This adds exactly
the three columns Team Management's new invite/role/leave endpoints need
to read and write per-membership: `role` ("admin" | "member" | "viewer",
checked directly in route handlers, not encoded as a DB constraint or
routed through the org-level Role/Permission machinery -- three fixed,
team-scoped values don't warrant that), `invited_by_user_id`, and
`joined_at`. `app/db/models.py` maps a new `TeamMember` class onto this
same table (SQLAlchemy's association-object pattern) purely for that
read/write access; `Team.members`'s existing `secondary=` relationship --
and the existing `PUT /orgs/{org_id}/teams/{id}/members` full-replace
endpoint built on it -- keeps working completely unchanged, per this
feature's decision to keep that endpoint rather than retire it.

`role` is added NOT NULL with `server_default='member'` so every
pre-existing team_memberships row (which predates any role concept at
all) comes out the other side classified as an ordinary member, not an
admin -- nobody's privilege silently increases as a side effect of this
migration. `invited_by_user_id` and `joined_at` are both nullable: a
pre-existing membership has no real invite event to backfill, so both
stay NULL for those rows rather than inventing a fake one.

Revision ID: 0020_team_member_roles
Revises: 0019_interactions
Create Date: 2026-08-10

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0020_team_member_roles"
down_revision: Union[str, None] = "0019_interactions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("teams") as batch_op:
        batch_op.add_column(sa.Column("description", sa.String(length=1000), nullable=True))
        batch_op.add_column(sa.Column("created_by_user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_teams_created_by_user_id", "users", ["created_by_user_id"], ["id"]
        )

    with op.batch_alter_table("team_memberships") as batch_op:
        batch_op.add_column(
            sa.Column("role", sa.String(length=20), nullable=False, server_default="member")
        )
        batch_op.add_column(sa.Column("invited_by_user_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("joined_at", sa.DateTime(), nullable=True))
        batch_op.create_foreign_key(
            "fk_team_memberships_invited_by_user_id", "users", ["invited_by_user_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("team_memberships") as batch_op:
        # FK constraint must be dropped before the column backing it --
        # same MySQL ordering constraint 0016_role_org_scope.py's
        # downgrade already documented (errno 1553 otherwise).
        batch_op.drop_constraint("fk_team_memberships_invited_by_user_id", type_="foreignkey")
        batch_op.drop_column("joined_at")
        batch_op.drop_column("invited_by_user_id")
        batch_op.drop_column("role")

    with op.batch_alter_table("teams") as batch_op:
        batch_op.drop_constraint("fk_teams_created_by_user_id", type_="foreignkey")
        batch_op.drop_column("created_by_user_id")
        batch_op.drop_column("description")
