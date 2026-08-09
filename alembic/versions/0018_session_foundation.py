"""Phase 4 PR-A (Session Foundation): sessions table

New table only -- no existing table altered, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at
0017_refresh_token_hash.

Mirrors 0013_mfa_foundation.py's "new table, FK'd + indexed on its owner,
separate op.create_index calls" shape. `session_id` is the refresh-token
family_id value (see app/db/models.py::UserSession's own docstring for
why there is deliberately no separate `refresh_token_family_id` column) --
not a foreign key to `refresh_tokens` itself, since `family_id` is not
unique on that table (every row in a family shares it) and a session must
keep existing even after every row in its family has been rotated away.

`organization_id` IS a real foreign key here (unlike, say, AuditEvent's
plain-int organization_id) -- this table lives in the same database as
`organizations`, so there is no cross-database trust-boundary reason to
avoid one, unlike the cross-repo case (e.g. omnibioai-billing) documented
elsewhere in this platform's architecture notes.

Revision ID: 0018_session_foundation
Revises: 0017_refresh_token_hash
Create Date: 2026-08-08

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0018_session_foundation"
down_revision: Union[str, None] = "0017_refresh_token_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("org_role", sa.JSON(), nullable=True),
        sa.Column("auth_method", sa.String(length=20), nullable=True),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=255), nullable=True),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
    )
    op.create_index("ix_sessions_session_id", "sessions", ["session_id"], unique=True)
    # (user_id, status): "my active sessions" -- the self-service list
    # endpoint's own query shape.
    op.create_index("ix_sessions_user_id_status", "sessions", ["user_id", "status"])
    # (organization_id, status, created_at): the org-scoped admin listing
    # a later Control Center integration PR adds -- schema is ready for it
    # now rather than needing a second migration then.
    op.create_index(
        "ix_sessions_org_id_status_created",
        "sessions",
        ["organization_id", "status", "created_at"],
    )
    # A future expiry sweep's scan order -- not used by any code in this
    # PR (see app/services/session_service.py's module docstring for why
    # EXPIRED is computed at read time, not swept), added now so that
    # sweep doesn't need its own migration later.
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])


def downgrade() -> None:
    # No explicit drop_index before drop_table -- on MySQL, user_id's and
    # organization_id's indexes also back their FK constraints, and MySQL
    # refuses to drop an index still "needed in a foreign key constraint"
    # even when the whole table is being dropped in the same statement
    # sequence. drop_table removes the table (and every index on it,
    # FK-backing or not) in one DDL statement, sidestepping the ordering
    # problem entirely -- same reasoning as 0013_mfa_foundation.py's
    # downgrade().
    op.drop_table("sessions")
