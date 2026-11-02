"""Validation, persistence, and notification state for research inquiries."""

import hashlib
import hmac
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.research_inquiry import ResearchInquiry
from app.schemas.research_inquiry import ResearchInquiryCreate
from app.services.email_delivery_service import EmailDeliveryError, send_research_inquiry_notification
from app.services.audit_service import log_event

CONSUMER_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "hotmail.com",
    "outlook.com", "live.com", "icloud.com", "aol.com", "proton.me", "protonmail.com",
})
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SECRET_LIKE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bbearer\s+\S+|\b(?:bearer|api[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+", re.I)
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", re.I)


class DuplicateInquiry(RuntimeError):
    pass


def validate_semantics(payload: ResearchInquiryCreate) -> dict[str, str]:
    errors: dict[str, str] = {}
    email = payload.institutional_email.lower()
    domain = email.rsplit("@", 1)[-1]
    local = email.split("@", 1)[0]
    if (not re.fullmatch(r"[^\s@]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", email, re.I)
            or domain in CONSUMER_DOMAINS or local.startswith(".") or local.endswith(".") or ".." in local
            or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local, re.I)):
        errors["institutional_email"] = "Enter a valid institutional email address."
    if payload.institutional_website:
        try:
            parsed = urlparse(payload.institutional_website)
            host = parsed.hostname or ""
            if (parsed.scheme not in {"http", "https"} or parsed.username or parsed.password
                    or not HOST.fullmatch(host) or any(c.isspace() for c in payload.institutional_website)
                    or "\\" in payload.institutional_website or parsed.port == 0):
                raise ValueError
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if (address is not None and not address.is_global) or host.lower() in {"localhost", "localhost.localdomain"}:
                raise ValueError
        except ValueError:
            errors["institutional_website"] = "Enter a complete public http or https institutional URL."
    for field in ("full_name", "institution", "department", "country", "proposed_collaboration", "potential_datasets", "additional_information"):
        if CONTROL.search(getattr(payload, field)):
            errors[field] = "Contains unsupported control characters."
    sensitive = "\n".join(value for value in payload.model_dump().values() if isinstance(value, str))
    if SECRET_LIKE.search(sensitive):
        errors["additional_information"] = "Remove credentials, tokens, or private keys before submitting."
    return errors


def duplicate_fingerprint(payload: ResearchInquiryCreate, submitted_at: datetime) -> str:
    # All material fields participate; different contacts/resources must not
    # collide just because they share an institution and proposal.
    values = payload.model_dump(exclude={"company_fax", "consent"})
    values["institutional_email"] = values["institutional_email"].lower()
    values["utc_day"] = submitted_at.date().isoformat()
    canonical = json.dumps(values, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return hmac.new(settings.RESEARCH_INQUIRY_HMAC_KEY.encode(), canonical, hashlib.sha256).hexdigest()


def create(db: Session, payload: ResearchInquiryCreate) -> ResearchInquiry:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = ResearchInquiry(
        inquiry_id=str(uuid.uuid4()),
        full_name=payload.full_name,
        institutional_email=str(payload.institutional_email).lower(),
        institution=payload.institution,
        department=payload.department,
        country=payload.country,
        research_interest=payload.research_interest,
        proposed_collaboration=payload.proposed_collaboration.replace("\r\n", "\n").replace("\r", "\n"),
        potential_datasets=payload.potential_datasets.replace("\r\n", "\n").replace("\r", "\n"),
        institutional_website=payload.institutional_website,
        additional_information=payload.additional_information.replace("\r\n", "\n").replace("\r", "\n"),
        consent_timestamp=now,
        submission_timestamp=now,
        processing_status="new",
        notification_status="pending",
        notification_attempts=0,
        duplicate_fingerprint=duplicate_fingerprint(payload, now),
        created_at=now,
        updated_at=now,
    )
    try:
        db.add(row)
        db.commit()
        db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        if db.query(ResearchInquiry.inquiry_id).filter_by(duplicate_fingerprint=row.duplicate_fingerprint).first():
            raise DuplicateInquiry from exc
        raise
    except Exception:
        db.rollback()
        raise
    return row


def notify(db: Session, row: ResearchInquiry, *, actor_user_id: int | None = None) -> bool:
    # Serialize retry state using the existing MySQL transaction. The provider
    # key protects the crash-after-delivery window; row locking alone cannot.
    row = db.query(ResearchInquiry).filter_by(inquiry_id=row.inquiry_id).populate_existing().with_for_update().one()
    if row.notification_status == "sent":
        return True
    if row.notification_attempts >= settings.RESEARCH_INQUIRY_NOTIFICATION_MAX_ATTEMPTS:
        row.notification_last_error = "retry_exhausted"
        db.commit()
        return False
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row.notification_last_attempt_at = now
    row.updated_at = now
    if not settings.RESEARCH_INQUIRY_NOTIFICATION_TO or not settings.RESEARCH_INQUIRY_NOTIFICATION_IDEMPOTENCY_CONFIRMED:
        row.notification_status = "not_configured"
        row.notification_last_error = "recipient_not_configured" if not settings.RESEARCH_INQUIRY_NOTIFICATION_TO else "provider_idempotency_unverified"
        db.commit()
        return False
    row.notification_attempts += 1
    if actor_user_id is not None:
        log_event(db, "research_inquiry_notification_retry", actor_user_id=actor_user_id,
                  resource_type="research_inquiry", resource_id=row.inquiry_id,
                  metadata={"attempt": row.notification_attempts}, commit=False)
    try:
        receipt = send_research_inquiry_notification(
            settings.RESEARCH_INQUIRY_NOTIFICATION_TO,
            inquiry_id=row.inquiry_id,
            full_name=row.full_name,
            institutional_email=row.institutional_email,
            institution=row.institution,
            department=row.department,
            country=row.country,
            research_interest=row.research_interest,
        )
        row.notification_status = "sent"
        row.notification_receipt_id = receipt
        row.notification_last_error = None
        db.commit()
        return True
    except EmailDeliveryError:
        row.notification_status = "failed"
        row.notification_last_error = "delivery_failed"
        db.commit()
        return False


def public_record(row: ResearchInquiry) -> dict:
    return {"status": "received", "inquiry_id": row.inquiry_id, "submitted_at": row.submission_timestamp.isoformat() + "Z"}


def admin_record(row: ResearchInquiry) -> dict:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns if column.name != "duplicate_fingerprint"}

def change_status(db: Session, row: ResearchInquiry, status: str, actor_user_id: int) -> None:
    before = row.processing_status
    row.processing_status = status
    row.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        log_event(db, "research_inquiry_status_changed", actor_user_id=actor_user_id,
                  resource_type="research_inquiry", resource_id=row.inquiry_id,
                  before_state={"status": before}, after_state={"status": status}, commit=False)
        db.commit()
    except Exception:
        db.rollback()
        raise
