"""Email MFA one-time codes.

Revision ID: 0034_email_mfa_otp
Revises: 0032_manual_license_security
"""
from typing import Union

from alembic import op
import sqlalchemy as sa


revision: str = "0034_email_mfa_otp"
down_revision: Union[str, None] = "0033_user_credential_epoch"
branch_labels = None
depends_on = None


def _precreated_email_otp_table_matches() -> bool:
    """Accept only the table shape produced by SQLAlchemy create_all()."""
    inspector = sa.inspect(op.get_bind())
    table_name = "mfa_email_otps"
    if not inspector.has_table(table_name):
        return False
    expected_columns = {
        "id", "user_id", "challenge_jti", "code_hash", "attempts",
        "created_at", "expires_at", "consumed_at", "invalidated_at",
    }
    actual_columns = {item["name"] for item in inspector.get_columns(table_name)}
    indexes = {item["name"] for item in inspector.get_indexes(table_name)}
    foreign_keys = {
        tuple(item["constrained_columns"])
        for item in inspector.get_foreign_keys(table_name)
    }
    expected_indexes = {
        "ix_mfa_email_otps_user_id",
        "ix_mfa_email_otps_user_created",
        "ix_mfa_email_otps_challenge_jti",
        "ix_mfa_email_otps_expires_at",
    }
    invalid = {
        "missing_columns": expected_columns - actual_columns,
        "unexpected_columns": actual_columns - expected_columns,
        "missing_indexes": expected_indexes - indexes,
        "missing_user_foreign_key": ("user_id",) not in foreign_keys,
    }
    if any(invalid.values()):
        raise RuntimeError(
            "Refusing email MFA migration: pre-existing mfa_email_otps "
            f"does not match the expected create_all schema ({invalid})."
        )
    return True


def upgrade() -> None:
    if _precreated_email_otp_table_matches():
        return
    op.create_table(
        "mfa_email_otps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("challenge_jti", sa.String(length=64), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
    )
    op.create_index("ix_mfa_email_otps_user_id", "mfa_email_otps", ["user_id"])
    op.create_index("ix_mfa_email_otps_user_created", "mfa_email_otps", ["user_id", "created_at"])
    op.create_index("ix_mfa_email_otps_challenge_jti", "mfa_email_otps", ["challenge_jti"])
    op.create_index("ix_mfa_email_otps_expires_at", "mfa_email_otps", ["expires_at"])


def downgrade() -> None:
    # Dropping the table also drops the MySQL-generated FK support index.
    op.drop_table("mfa_email_otps")
