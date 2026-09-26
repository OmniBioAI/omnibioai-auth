"""Add nullable integrity metadata and storage-level append-only guards.

Existing audit rows are not updated: NULL integrity columns identify them
as legacy/unsigned. Database triggers reject UPDATE and DELETE regardless
of the application API.

Revision ID: 0028_auth_audit_integrity
Revises: 0027_delegated_execution_grants
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0028_auth_audit_integrity"
down_revision: Union[str, None] = "0027_delegated_execution_grants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.add_column(sa.Column("integrity_version", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("integrity_algorithm", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("integrity_digest", sa.String(length=64), nullable=True))

    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("""
            CREATE TRIGGER auth_audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END
        """)
        op.execute("""
            CREATE TRIGGER auth_audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END
        """)
    elif dialect == "mysql":
        op.execute("""
            CREATE TRIGGER auth_audit_events_no_update
            BEFORE UPDATE ON audit_events FOR EACH ROW
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only'
        """)
        op.execute("""
            CREATE TRIGGER auth_audit_events_no_delete
            BEFORE DELETE ON audit_events FOR EACH ROW
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only'
        """)
    else:
        raise RuntimeError(f"Append-only audit triggers are not implemented for {dialect}")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS auth_audit_events_no_delete")
        op.execute("DROP TRIGGER IF EXISTS auth_audit_events_no_update")
    elif dialect == "mysql":
        op.execute("DROP TRIGGER IF EXISTS auth_audit_events_no_delete")
        op.execute("DROP TRIGGER IF EXISTS auth_audit_events_no_update")
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_column("integrity_digest")
        batch_op.drop_column("integrity_algorithm")
        batch_op.drop_column("integrity_version")
