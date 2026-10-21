"""Track short-lived, single-use pre-authentication MFA enrollment sessions.

Revision ID: 0036_mfa_enrollment_sessions
Revises: 0035_organization_invitations
"""
from alembic import op
import sqlalchemy as sa


revision = "0036_mfa_enrollment_sessions"
down_revision = "0035_organization_invitations"
branch_labels = None
depends_on = None


def _existing_table_matches() -> bool:
    inspector = sa.inspect(op.get_bind())
    table = "mfa_enrollment_sessions"
    if not inspector.has_table(table):
        return False
    expected_columns = {
        "id", "user_id", "token_jti", "device_id", "created_at", "expires_at", "consumed_at",
    }
    actual_columns = {column["name"] for column in inspector.get_columns(table)}
    unique_columns = {
        tuple(item["column_names"])
        for item in inspector.get_unique_constraints(table)
    }
    indexes = {item["name"] for item in inspector.get_indexes(table)}
    foreign_keys = {
        tuple(item["constrained_columns"])
        for item in inspector.get_foreign_keys(table)
    }
    expected_indexes = {"ix_mfa_enrollment_sessions_user_id", "ix_mfa_enrollment_sessions_expires_at"}
    if (
        actual_columns != expected_columns
        or not {("token_jti",), ("device_id",)}.issubset(unique_columns)
        or not expected_indexes.issubset(indexes)
        or not {("user_id",), ("device_id",)}.issubset(foreign_keys)
    ):
        raise RuntimeError(
            "Refusing MFA enrollment-session migration: existing table does not match the expected schema."
        )
    return True


def upgrade() -> None:
    if _existing_table_matches():
        return
    op.create_table(
        "mfa_enrollment_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_jti", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["device_id"], ["mfa_devices.id"]),
        sa.UniqueConstraint("token_jti", name="uq_mfa_enrollment_sessions_token_jti"),
        sa.UniqueConstraint("device_id", name="uq_mfa_enrollment_sessions_device_id"),
    )
    op.create_index("ix_mfa_enrollment_sessions_user_id", "mfa_enrollment_sessions", ["user_id"])
    op.create_index("ix_mfa_enrollment_sessions_expires_at", "mfa_enrollment_sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_table("mfa_enrollment_sessions")
