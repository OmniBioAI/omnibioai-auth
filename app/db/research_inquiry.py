"""Relational persistence model for public research collaboration inquiries."""

from sqlalchemy import CheckConstraint, Column, DateTime, Index, Integer, String, Text, UniqueConstraint

from app.db.base import Base


class ResearchInquiry(Base):
    __tablename__ = "research_inquiries"
    __table_args__ = (
        CheckConstraint("processing_status IN ('new','in_review','contacted','closed','spam')", name="ck_research_inquiry_status"),
        CheckConstraint("notification_status IN ('pending','sent','failed','not_configured')", name="ck_research_notification_status"),
        UniqueConstraint("duplicate_fingerprint", name="uq_research_inquiry_duplicate"),
        Index("ix_research_inquiry_submitted", "submission_timestamp", "inquiry_id"),
        Index("ix_research_inquiry_processing", "processing_status", "submission_timestamp"),
        Index("ix_research_inquiry_notification", "notification_status", "notification_last_attempt_at"),
    )

    inquiry_id = Column(String(36), primary_key=True)
    full_name = Column(String(120), nullable=False)
    institutional_email = Column(String(254), nullable=False)
    institution = Column(String(200), nullable=False)
    department = Column(String(160), nullable=False)
    country = Column(String(100), nullable=False)
    research_interest = Column(String(64), nullable=False)
    proposed_collaboration = Column(Text, nullable=False)
    potential_datasets = Column(Text, nullable=False, default="")
    institutional_website = Column(String(500), nullable=False, default="")
    additional_information = Column(Text, nullable=False, default="")
    consent_timestamp = Column(DateTime, nullable=False)
    submission_timestamp = Column(DateTime, nullable=False)
    processing_status = Column(String(32), nullable=False, default="new")
    notification_status = Column(String(32), nullable=False, default="pending")
    notification_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    notification_receipt_id = Column(String(255), nullable=True)
    notification_last_error = Column(String(64), nullable=True)
    notification_last_attempt_at = Column(DateTime, nullable=True)
    duplicate_fingerprint = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
