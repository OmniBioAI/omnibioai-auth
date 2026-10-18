"""Add secure, expiring organization invitations.

Revision ID: 0035_organization_invitations
Revises: 0034_email_mfa_otp
"""
from alembic import op
import sqlalchemy as sa


revision = "0035_organization_invitations"
down_revision = "0034_email_mfa_otp"
branch_labels = None
depends_on = None


def _existing_table_matches() -> bool:
    inspector = sa.inspect(op.get_bind())
    table = "organization_invitations"
    if not inspector.has_table(table):
        return False
    expected = {
        "id", "organization_id", "invited_by_user_id", "inviter_is_platform_admin", "invited_email", "role_names",
        "token_hash", "active_key", "status", "created_at", "expires_at", "accepted_at",
        "accepted_user_id", "revoked_at", "revoked_by_user_id", "mfa_secret_encrypted",
        "mfa_setup_at", "mfa_attempts",
    }
    actual = {column["name"] for column in inspector.get_columns(table)}
    unique_columns = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(table)
    }
    indexes = {index["name"] for index in inspector.get_indexes(table)}
    expected_indexes = {"ix_org_invitations_org_status", "ix_org_invitations_expires_at"}
    if actual != expected or not {
        ("token_hash",), ("active_key",)
    }.issubset(unique_columns) or not expected_indexes.issubset(indexes):
        raise RuntimeError(
            "Refusing organization-invitation migration: existing table does not match the expected schema."
        )
    return True


def upgrade() -> None:
    if _existing_table_matches():
        return
    op.create_table(
        "organization_invitations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=False),
        sa.Column("inviter_is_platform_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("invited_email", sa.String(length=255), nullable=False),
        sa.Column("role_names", sa.JSON(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("active_key", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.Column("accepted_user_id", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by_user_id", sa.Integer(), nullable=True),
        sa.Column("mfa_secret_encrypted", sa.String(length=1000), nullable=True),
        sa.Column("mfa_setup_at", sa.DateTime(), nullable=True),
        sa.Column("mfa_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["accepted_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"]),
        sa.UniqueConstraint("token_hash", name="uq_org_invitations_token_hash"),
        sa.UniqueConstraint("active_key", name="uq_org_invitations_active_key"),
    )
    op.create_index(
        "ix_org_invitations_org_status", "organization_invitations", ["organization_id", "status"]
    )
    op.create_index("ix_org_invitations_expires_at", "organization_invitations", ["expires_at"])


def downgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("organization_invitations"):
        op.drop_table("organization_invitations")
