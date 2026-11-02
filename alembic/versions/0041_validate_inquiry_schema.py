"""Validate the 0037–0040 schema and recover interrupted inquiry index creation.

Forward-only qualification guard: do not silently stamp lookalike precreated
tables. Earlier revision files and existing license data are not rewritten.
"""
import re

from alembic import op
import sqlalchemy as sa

revision = "0041_validate_inquiry_schema"
down_revision = "0040_research_inquiries"
branch_labels = None
depends_on = None


def _columns(table, expected, *, exact=True):
    columns = {c["name"]: c for c in sa.inspect(op.get_bind()).get_columns(table)}
    if (exact and set(columns) != set(expected)) or not set(expected) <= set(columns):
        raise RuntimeError(f"Incompatible {table} columns; operator recovery required")
    for name, (kind, length, nullable) in expected.items():
        actual = columns[name]
        if (actual["type"]._type_affinity is not kind()._type_affinity
                or (kind is sa.Text and not isinstance(actual["type"], sa.Text))
                or (length is not None and getattr(actual["type"], "length", None) != length)
                or actual["nullable"] != nullable):
            raise RuntimeError(f"Incompatible {table}.{name}; operator recovery required")
    return columns


def _sql(value):
    return re.sub(r"[\s`()]+", "", value.lower().replace("_utf8mb4", ""))


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if bind.dialect.name == "mysql" and bind.dialect.server_version_info < (8, 0, 16):
        raise RuntimeError("Research inquiries require enforced MySQL CHECK constraints (8.0.16+)")
    _columns("license_keys", {"key_pepper_id": (sa.String, 64, True)}, exact=False)
    _columns("license_generation_idempotency", {
        "id": (sa.Integer, None, False), "actor_key": (sa.String, 128, False),
        "idempotency_key_hash": (sa.String, 64, False), "request_fingerprint": (sa.String, 64, False),
        "license_id": (sa.Integer, None, False), "created_at": (sa.DateTime, None, False),
        "replay_envelope": (sa.Text, None, True), "encryption_key_id": (sa.String, 64, True),
        "converted_at": (sa.DateTime, None, True),
    })
    unique = {tuple(c["column_names"]) for c in inspector.get_unique_constraints("license_generation_idempotency")}
    foreign = inspector.get_foreign_keys("license_generation_idempotency")
    if (not {("actor_key", "idempotency_key_hash"), ("license_id",)} <= unique
            or not any(c["constrained_columns"] == ["license_id"] and c["referred_table"] == "license_keys"
                       and c["referred_columns"] == ["id"] for c in foreign)):
        raise RuntimeError("Incompatible license replay constraints; operator recovery required")
    table = "research_inquiries"
    columns = _columns(table, {
        "inquiry_id": (sa.String, 36, False), "full_name": (sa.String, 120, False),
        "institutional_email": (sa.String, 254, False), "institution": (sa.String, 200, False),
        "department": (sa.String, 160, False), "country": (sa.String, 100, False),
        "research_interest": (sa.String, 64, False), "proposed_collaboration": (sa.Text, None, False),
        "potential_datasets": (sa.Text, None, False), "institutional_website": (sa.String, 500, False),
        "additional_information": (sa.Text, None, False), "consent_timestamp": (sa.DateTime, None, False),
        "submission_timestamp": (sa.DateTime, None, False), "processing_status": (sa.String, 32, False),
        "notification_status": (sa.String, 32, False), "notification_attempts": (sa.Integer, None, False),
        "notification_receipt_id": (sa.String, 255, True), "notification_last_error": (sa.String, 64, True),
        "notification_last_attempt_at": (sa.DateTime, None, True), "duplicate_fingerprint": (sa.String, 64, False),
        "created_at": (sa.DateTime, None, False), "updated_at": (sa.DateTime, None, False),
    })
    if (inspector.get_pk_constraint(table)["constrained_columns"] != ["inquiry_id"]
            or inspector.get_foreign_keys(table)
            or str(columns["notification_attempts"]["default"]).strip("'()") != "0"
            or any(c["default"] is not None for n, c in columns.items() if n != "notification_attempts")):
        raise RuntimeError("Incompatible inquiry keys/defaults; operator recovery required")
    unique = {tuple(c["column_names"]) for c in inspector.get_unique_constraints(table)}
    if ("duplicate_fingerprint",) not in unique:
        raise RuntimeError("Missing inquiry duplicate constraint; operator recovery required")
    checks = {c["name"]: _sql(c["sqltext"]) for c in inspector.get_check_constraints(table)}
    required = {
        "ck_research_inquiry_status": "processing_status IN ('new','in_review','contacted','closed','spam')",
        "ck_research_notification_status": "notification_status IN ('pending','sent','failed','not_configured')",
    }
    if any(checks.get(n) != _sql(sql) for n, sql in required.items()):
        raise RuntimeError("Incompatible inquiry status constraints; operator recovery required")
    indexes = {c["name"]: c for c in inspector.get_indexes(table)}
    required_indexes = {
        "ix_research_inquiry_submitted": ["submission_timestamp", "inquiry_id"],
        "ix_research_inquiry_processing": ["processing_status", "submission_timestamp"],
        "ix_research_inquiry_notification": ["notification_status", "notification_last_attempt_at"],
    }
    for name, names in required_indexes.items():
        if name not in indexes:
            op.create_index(name, table, names)
        elif indexes[name]["column_names"] != names or indexes[name]["unique"]:
            raise RuntimeError("Incompatible inquiry index; operator recovery required")


def downgrade():
    # Validation has no destructive inverse; keep recovered indexes. 0040
    # remains responsible for refusing to drop any populated inquiry table.
    pass
