"""Add authenticated ciphertext storage for license-generation replay.

Revision ID: 0038_encrypt_license_replay
Revises: 0037_license_generation_idem

This schema migration is deliberately additive.  Legacy plaintext conversion
is a separate, resumable operator action performed only after encryption-key
custody and protected backups have been verified.
"""

from alembic import op
import sqlalchemy as sa


revision = "0038_encrypt_license_replay"
down_revision = "0037_license_generation_idem"
branch_labels = None
depends_on = None

_TABLE = "license_generation_idempotency"
_COLUMNS = {
    "replay_envelope": sa.Text(),
    "encryption_key_id": sa.String(length=64),
    "converted_at": sa.DateTime(),
}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"]: column for column in inspector.get_columns(_TABLE)}
    for name, column_type in _COLUMNS.items():
        if name not in existing:
            op.add_column(_TABLE, sa.Column(name, column_type, nullable=True))
        elif not existing[name]["nullable"]:
            raise RuntimeError(
                "Existing encrypted replay schema is incompatible; operator recovery required"
            )
    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(_TABLE)}
    if "ix_license_generation_encryption_key_id" not in indexes:
        op.create_index(
            "ix_license_generation_encryption_key_id", _TABLE, ["encryption_key_id"], unique=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    encrypted = bind.execute(
        sa.text(
            "SELECT 1 FROM license_generation_idempotency "
            "WHERE replay_envelope IS NOT NULL OR encryption_key_id IS NOT NULL LIMIT 1"
        )
    ).first()
    if encrypted:
        raise RuntimeError(
            "Cannot remove encrypted replay history; retain schema and roll forward"
        )
    inspector = sa.inspect(bind)
    existing = {column["name"] for column in inspector.get_columns(_TABLE)}
    indexes = {index["name"] for index in inspector.get_indexes(_TABLE)}
    if "ix_license_generation_encryption_key_id" in indexes:
        op.drop_index("ix_license_generation_encryption_key_id", table_name=_TABLE)
    for name in ("converted_at", "encryption_key_id", "replay_envelope"):
        if name in existing:
            op.drop_column(_TABLE, name)
