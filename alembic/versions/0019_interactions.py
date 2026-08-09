"""PR-B2 (Interactions Foundation): interactions table

New table only -- no existing table altered, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at
0018_session_foundation.

Mirrors 0018_session_foundation.py's "new table, indexed on its owner,
separate op.create_index calls" shape, but follows AuditEvent's (0011)
plain-int/no-FK convention for organization_id/user_id, not
UserSession's real-FK convention -- see app/db/models.py::Interaction's
own docstring for why: a durable ledger row must keep its historical
identifiers even if the referenced organization/user is later deleted,
the same reasoning AuditEvent's 0011 migration already established for
this schema. session_id is a plain string correlating to
UserSession.session_id by value, not a foreign key to it, for the
identical reason.

Revision ID: 0019_interactions
Revises: 0018_session_foundation
Create Date: 2026-08-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0019_interactions"
down_revision: Union[str, None] = "0018_session_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "interactions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("interaction_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("trace_id", sa.String(length=255), nullable=True),
        sa.Column("service", sa.String(length=100), nullable=False),
        sa.Column("interaction_type", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("decision", sa.String(length=50), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_interactions_interaction_id", "interactions", ["interaction_id"], unique=True
    )
    op.create_index("ix_interactions_trace_id", "interactions", ["trace_id"])
    # Org-scoped listing, newest first -- the primary anticipated query
    # shape (a future org-scoped Control Center view, PR-B5+).
    op.create_index(
        "ix_interactions_org_id_created", "interactions", ["organization_id", "created_at"]
    )
    # "My interactions" / "this session's interactions".
    op.create_index(
        "ix_interactions_user_id_created", "interactions", ["user_id", "created_at"]
    )
    op.create_index(
        "ix_interactions_session_id_created", "interactions", ["session_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("interactions")
