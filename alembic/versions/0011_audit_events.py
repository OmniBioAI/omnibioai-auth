"""PR9 (Enterprise IAM Foundation): audit_events table

New table only -- no existing table altered, renamed, or dropped. Safe to
`alembic upgrade head` on any environment already at 0010_role_description.

actor_user_id/target_user_id/organization_id are plain nullable integer
columns, deliberately not foreign keys -- an audit row must remain valid
and keep its historical identifiers even if a referenced user/org row is
ever deleted in the future, matching how AuditEvent (app/db/models.py) is
documented. `metadata` is the actual column name (the ORM attribute is
named `event_metadata` -- `metadata` is reserved on SQLAlchemy's
declarative Base).

Revision ID: 0011_audit_events
Revises: 0010_role_description
Create Date: 2026-08-04

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0011_audit_events"
down_revision: Union[str, None] = "0010_role_description"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(length=100), nullable=True),
        sa.Column("before_state", sa.JSON(), nullable=True),
        sa.Column("after_state", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_target_user_id", "audit_events", ["target_user_id"])
    op.create_index("ix_audit_events_organization_id", "audit_events", ["organization_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
