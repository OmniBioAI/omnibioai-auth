"""Identify the pepper version used for each digest-only license.

Revision ID: 0039_version_license_key_peppers
Revises: 0038_encrypt_license_replay

Existing rows remain NULL and continue using the legacy unversioned pepper.
No digest is rewritten by this schema migration.
"""
from alembic import op
import sqlalchemy as sa


revision = "0039_version_license_key_peppers"
down_revision = "0038_encrypt_license_replay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("license_keys")}
    if "key_pepper_id" not in columns:
        op.add_column("license_keys", sa.Column("key_pepper_id", sa.String(64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text(
        "SELECT 1 FROM license_keys WHERE key_pepper_id IS NOT NULL LIMIT 1"
    )).first():
        raise RuntimeError(
            "Cannot remove pepper-version identity from license digests; retain schema and roll forward"
        )
    columns = {column["name"] for column in sa.inspect(bind).get_columns("license_keys")}
    if "key_pepper_id" in columns:
        op.drop_column("license_keys", "key_pepper_id")
