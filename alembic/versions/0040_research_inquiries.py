"""Add durable research collaboration inquiries.

Revision ID: 0040_research_inquiries
Revises: 0039_version_license_key_peppers
"""
from alembic import op
import sqlalchemy as sa


revision = "0040_research_inquiries"
down_revision = "0039_version_license_key_peppers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("research_inquiries"):
        expected = {
            "inquiry_id", "full_name", "institutional_email", "institution", "department", "country",
            "research_interest", "proposed_collaboration", "potential_datasets", "institutional_website",
            "additional_information", "consent_timestamp", "submission_timestamp", "processing_status",
            "notification_status", "notification_attempts", "notification_receipt_id",
            "notification_last_error", "notification_last_attempt_at", "duplicate_fingerprint",
            "created_at", "updated_at",
        }
        if {column["name"] for column in inspector.get_columns("research_inquiries")} != expected:
            raise RuntimeError("Existing research inquiry schema is incompatible; operator recovery required")
        return
    op.create_table(
        "research_inquiries",
        sa.Column("inquiry_id", sa.String(36), primary_key=True),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("institutional_email", sa.String(254), nullable=False),
        sa.Column("institution", sa.String(200), nullable=False),
        sa.Column("department", sa.String(160), nullable=False),
        sa.Column("country", sa.String(100), nullable=False),
        sa.Column("research_interest", sa.String(64), nullable=False),
        sa.Column("proposed_collaboration", sa.Text(), nullable=False),
        sa.Column("potential_datasets", sa.Text(), nullable=False),
        sa.Column("institutional_website", sa.String(500), nullable=False),
        sa.Column("additional_information", sa.Text(), nullable=False),
        sa.Column("consent_timestamp", sa.DateTime(), nullable=False),
        sa.Column("submission_timestamp", sa.DateTime(), nullable=False),
        sa.Column("processing_status", sa.String(32), nullable=False),
        sa.Column("notification_status", sa.String(32), nullable=False),
        sa.Column("notification_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("notification_receipt_id", sa.String(255), nullable=True),
        sa.Column("notification_last_error", sa.String(64), nullable=True),
        sa.Column("notification_last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("duplicate_fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("processing_status IN ('new','in_review','contacted','closed','spam')", name="ck_research_inquiry_status"),
        sa.CheckConstraint("notification_status IN ('pending','sent','failed','not_configured')", name="ck_research_notification_status"),
        sa.UniqueConstraint("duplicate_fingerprint", name="uq_research_inquiry_duplicate"),
    )
    op.create_index("ix_research_inquiry_submitted", "research_inquiries", ["submission_timestamp", "inquiry_id"])
    op.create_index("ix_research_inquiry_processing", "research_inquiries", ["processing_status", "submission_timestamp"])
    op.create_index("ix_research_inquiry_notification", "research_inquiries", ["notification_status", "notification_last_attempt_at"])


def downgrade() -> None:
    row = op.get_bind().execute(sa.text("SELECT 1 FROM research_inquiries LIMIT 1")).first()
    if row:
        raise RuntimeError("Cannot remove populated research inquiries; retain data and roll forward")
    op.drop_index("ix_research_inquiry_notification", table_name="research_inquiries")
    op.drop_index("ix_research_inquiry_processing", table_name="research_inquiries")
    op.drop_index("ix_research_inquiry_submitted", table_name="research_inquiries")
    op.drop_table("research_inquiries")
