"""Harden new license storage and add issuance idempotency.

Existing plaintext license keys are deliberately left untouched.  New code
writes key=NULL plus a keyed digest; the compatibility lookup remains until a
separately tested live-data migration is approved.
"""
from alembic import op
import sqlalchemy as sa

revision = "0032_manual_license_security"
down_revision = "0031_integration_credentials"
branch_labels = None
depends_on = None


def _precreated_license_columns_match():
    """Recognize only the exact additive shape produced by create_all()."""
    inspector = sa.inspect(op.get_bind())
    columns = {item["name"]: item for item in inspector.get_columns("license_keys")}
    expected = {"key_digest", "key_prefix", "recipient_name", "renewed_at"}
    present = expected & set(columns)
    if not present:
        return False

    indexes = {item["name"]: item for item in inspector.get_indexes("license_keys")}
    missing = expected - present
    digest_index = indexes.get("ix_license_keys_key_digest")
    invalid = {
        "missing_columns": missing,
        "key_is_not_nullable": not columns["key"]["nullable"],
        "missing_or_nonunique_digest_index": not digest_index or not digest_index.get("unique"),
    }
    if missing or invalid["key_is_not_nullable"] or invalid["missing_or_nonunique_digest_index"]:
        raise RuntimeError(
            "Refusing manual-license migration: pre-existing license security "
            f"columns do not match the expected create_all schema ({invalid})."
        )
    return True


def _precreated_issuance_table_matches():
    """Accept create_all ordering, while failing closed on lookalike tables."""
    inspector = sa.inspect(op.get_bind())
    table_name = "license_issuance_requests"
    if not inspector.has_table(table_name):
        return False

    expected_columns = {
        "id", "actor_user_id", "idempotency_key_hash", "request_fingerprint",
        "license_id", "created_at",
    }
    actual_columns = {item["name"] for item in inspector.get_columns(table_name)}
    constraints = {
        item["name"] for item in inspector.get_unique_constraints(table_name)
    }
    constraints.update(item["name"] for item in inspector.get_indexes(table_name))
    foreign_keys = {
        tuple(item["constrained_columns"])
        for item in inspector.get_foreign_keys(table_name)
    }
    invalid = {
        "missing_columns": expected_columns - actual_columns,
        "unexpected_columns": actual_columns - expected_columns,
        "missing_unique_constraint": "uq_license_issue_actor_key" not in constraints,
        "missing_foreign_keys": {("actor_user_id",), ("license_id",)} - foreign_keys,
    }
    if any(invalid.values()):
        raise RuntimeError(
            "Refusing manual-license migration: pre-existing "
            f"{table_name} does not match the expected create_all schema ({invalid})."
        )
    return True


def upgrade():
    if not _precreated_license_columns_match():
        if op.get_bind().dialect.name == "sqlite":
            # SQLite has no ALTER COLUMN DROP NOT NULL (SQLAlchemy 2.1
            # correctly emits that unsupported syntax). Batch mode rebuilds
            # the table with the same nullable column while preserving its
            # existing indexes, constraints, and rows.
            with op.batch_alter_table("license_keys") as batch_op:
                batch_op.alter_column("key", existing_type=sa.String(29), nullable=True)
        else:
            # Keep the production MySQL DDL identical to the established
            # direct ALTER TABLE operation.
            op.alter_column("license_keys", "key", existing_type=sa.String(29), nullable=True)
        op.add_column("license_keys", sa.Column("key_digest", sa.String(64), nullable=True))
        op.add_column("license_keys", sa.Column("key_prefix", sa.String(9), nullable=True))
        op.add_column("license_keys", sa.Column("recipient_name", sa.String(255), nullable=True))
        op.add_column("license_keys", sa.Column("renewed_at", sa.DateTime(), nullable=True))
        op.create_index("ix_license_keys_key_digest", "license_keys", ["key_digest"], unique=True)

    if not _precreated_issuance_table_matches():
        op.create_table(
            "license_issuance_requests",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("idempotency_key_hash", sa.String(64), nullable=False),
            sa.Column("request_fingerprint", sa.String(64), nullable=False),
            sa.Column("license_id", sa.Integer(), sa.ForeignKey("license_keys.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("actor_user_id", "idempotency_key_hash", name="uq_license_issue_actor_key"),
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("license_keys") and "key_digest" in {
        item["name"] for item in inspector.get_columns("license_keys")
    }:
        digest_rows = bind.execute(
            sa.text("SELECT COUNT(*) FROM license_keys WHERE key_digest IS NOT NULL")
        ).scalar_one()
        if digest_rows:
            raise RuntimeError(
                "Refusing manual-license downgrade while digest-only licenses exist; "
                "they cannot be validated after key_digest is removed."
            )
    op.drop_table("license_issuance_requests")
    op.drop_index("ix_license_keys_key_digest", table_name="license_keys")
    op.drop_column("license_keys", "renewed_at")
    op.drop_column("license_keys", "recipient_name")
    op.drop_column("license_keys", "key_prefix")
    op.drop_column("license_keys", "key_digest")
    # A downgrade is safe only when no digest-only row exists.
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("license_keys") as batch_op:
            batch_op.alter_column("key", existing_type=sa.String(29), nullable=False)
    else:
        op.alter_column("license_keys", "key", existing_type=sa.String(29), nullable=False)
