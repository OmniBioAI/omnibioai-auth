"""Persist replayable results for OAuth license generation.

Revision ID: 0037_license_generation_idem
Revises: 0036_mfa_enrollment_sessions
"""
from alembic import op
import sqlalchemy as sa


revision = "0037_license_generation_idem"
down_revision = "0036_mfa_enrollment_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # MySQL DDL can commit before Alembic records the revision. Permit a
    # restart only when the existing table matches the intended constraints.
    inspector = sa.inspect(op.get_bind())
    table = "license_generation_idempotency"
    if inspector.has_table(table):
        columns = inspector.get_columns(table)
        expected = {"id", "actor_key", "idempotency_key_hash", "request_fingerprint", "license_id", "created_at"}
        unique = {tuple(c["column_names"]) for c in inspector.get_unique_constraints(table)}
        foreign = inspector.get_foreign_keys(table)
        allowed = expected | {"replay_envelope", "encryption_key_id", "converted_at"}
        by_name = {c["name"]: c for c in columns}
        if (not expected <= set(by_name)
                or not set(by_name) <= allowed
                or any(by_name[name]["nullable"] for name in expected)
                or not {("actor_key", "idempotency_key_hash"), ("license_id",)} <= unique
                or not any(f["constrained_columns"] == ["license_id"] and f["referred_table"] == "license_keys" and f["referred_columns"] == ["id"] for f in foreign)):
            raise RuntimeError("Existing license generation history schema is incompatible; operator recovery required")
        return
    op.create_table(
        "license_generation_idempotency",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_key", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("license_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["license_id"], ["license_keys.id"]),
        sa.UniqueConstraint("actor_key", "idempotency_key_hash", name="uq_license_generation_actor_key"),
        sa.UniqueConstraint("license_id", name="uq_license_generation_license"),
    )


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT 1 FROM license_generation_idempotency LIMIT 1")).first():
        raise RuntimeError("Cannot remove populated issuance history; retain schema and roll forward")
    op.drop_table("license_generation_idempotency")
