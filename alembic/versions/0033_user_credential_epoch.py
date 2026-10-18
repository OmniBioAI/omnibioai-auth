"""Add a monotonic per-user credential epoch for access-token revocation."""
from alembic import op
import sqlalchemy as sa


revision = "0033_user_credential_epoch"
down_revision = "0032_manual_license_security"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"]: item for item in sa.inspect(op.get_bind()).get_columns("users")}
    if "credential_version" not in columns:
        op.add_column(
            "users",
            sa.Column("credential_version", sa.Integer(), nullable=False, server_default="0"),
        )
    elif columns["credential_version"]["nullable"]:
        raise RuntimeError("Refusing credential-epoch migration: existing column is nullable")


def downgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("users")}
    if "credential_version" in columns:
        op.drop_column("users", "credential_version")
