"""Public submission and role-gated administration for research inquiries."""

import hashlib
import ipaddress
import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session
from prometheus_client import Counter
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.core.rate_limit import is_locked, record_attempt
from app.db.research_inquiry import ResearchInquiry
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.research_inquiry import ResearchInquiryCreate, ResearchInquiryStatusUpdate
from app.services import research_inquiry_service as service

router = APIRouter(tags=["research-inquiries"])
_require_platform_admin = require_permission(MANAGE_ALL_ORGS)
MAX_REQUEST_BYTES = 16_384
SUBMISSIONS = Counter("auth_research_inquiry_submissions_total", "Research inquiry submission outcomes", ["outcome"])
NOTIFICATIONS = Counter("auth_research_inquiry_notifications_total", "Research inquiry notification outcomes", ["outcome"])


def _error(status: int, message: str, *, fields: dict | None = None, headers: dict | None = None):
    body = {"error": message}
    if fields:
        body["field_errors"] = fields
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store", **(headers or {})})


def _client_address(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    candidate = peer
    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return "unknown"
    if any(peer_address in network for network in settings.RESEARCH_INQUIRY_TRUSTED_PROXIES):
        candidate = request.headers.get("CF-Connecting-IP", peer)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unknown"


def _rate_limit(request: Request):
    subject = hashlib.sha256(_client_address(request).encode()).hexdigest()
    fail_key = f"research-inquiry:rate:{subject}"
    lock_key = f"research-inquiry:lock:{subject}"
    locked, retry_after = is_locked(lock_key)
    if locked:
        return _error(429, "Too many requests", headers={"Retry-After": str(max(1, retry_after))})
    result = record_attempt(
        fail_key, lock_key,
        settings.RESEARCH_INQUIRY_RATE_WINDOW_SECONDS,
        settings.RESEARCH_INQUIRY_RATE_LIMIT + 1,
        settings.RESEARCH_INQUIRY_RATE_WINDOW_SECONDS,
        fallback_window_seconds=settings.RESEARCH_INQUIRY_RATE_WINDOW_SECONDS,
        fallback_max_attempts=settings.RESEARCH_INQUIRY_RATE_LIMIT + 1,
    )
    if result.locked:
        return _error(429, "Too many requests", headers={"Retry-After": str(settings.RESEARCH_INQUIRY_RATE_WINDOW_SECONDS)})
    return None


@router.post("/api/v1/research-inquiries", status_code=201)
async def submit_research_inquiry(request: Request, db: Session = Depends(get_db)):
    origin = request.headers.get("origin")
    if origin and origin not in settings.CORS_ALLOWED_ORIGINS:
        return _error(403, "Origin is not allowed")
    if not settings.RESEARCH_INQUIRY_ENABLED:
        SUBMISSIONS.labels("disabled").inc()
        return _error(503, "Inquiry service unavailable")
    limited = await run_in_threadpool(_rate_limit, request)
    if limited:
        SUBMISSIONS.labels("rate_limited").inc()
        return limited
    if (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower() != "application/json":
        return _error(415, "Content-Type must be application/json")
    declared = request.headers.get("content-length")
    if declared and (not declared.isdecimal() or int(declared) > MAX_REQUEST_BYTES):
        return _error(413, "Request is too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            return _error(413, "Request is too large")
        body.extend(chunk)
    try:
        raw = json.loads(body.decode("utf-8"))
        payload = ResearchInquiryCreate.model_validate(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(400, "Invalid JSON request")
    except ValidationError as exc:
        fields = {}
        for issue in exc.errors(include_url=False, include_input=False):
            key = str(issue["loc"][0]) if issue.get("loc") else "request"
            fields.setdefault(key, "Invalid value.")
        return _error(422, "Validation failed", fields=fields)
    if payload.company_fax:
        SUBMISSIONS.labels("honeypot").inc()
        return Response(status_code=204, headers={"Cache-Control": "no-store"})
    semantic_errors = service.validate_semantics(payload)
    if semantic_errors:
        return _error(422, "Validation failed", fields=semantic_errors)
    return await run_in_threadpool(_persist_and_notify, db, payload)


def _persist_and_notify(db: Session, payload: ResearchInquiryCreate):
    try:
        row = service.create(db, payload)
        persisted_response = service.public_record(row)
    except service.DuplicateInquiry:
        SUBMISSIONS.labels("duplicate").inc()
        return _error(409, "A matching inquiry was already submitted recently")
    except Exception:
        db.rollback()
        SUBMISSIONS.labels("persistence_failed").inc()
        return _error(503, "Inquiry could not be recorded")
    try:
        sent = service.notify(db, row)
        NOTIFICATIONS.labels("sent" if sent else row.notification_status).inc()
    except Exception:
        db.rollback()
        NOTIFICATIONS.labels("state_update_failed").inc()
        # The durable record remains valid; pending notification is retryable.
    SUBMISSIONS.labels("persisted").inc()
    return JSONResponse(persisted_response, status_code=201, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/admin/research-inquiries")
def list_research_inquiries(
    response: Response,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    status: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _admin=Depends(_require_platform_admin),
):
    response.headers["Cache-Control"] = "no-store"
    query = db.query(ResearchInquiry)
    if status:
        if status not in {"new", "in_review", "contacted", "closed", "spam"}:
            raise HTTPException(status_code=422, detail="Invalid processing status")
        query = query.filter(ResearchInquiry.processing_status == status)
    total = query.count()
    rows = query.order_by(ResearchInquiry.submission_timestamp.desc(), ResearchInquiry.inquiry_id.desc()).offset(offset).limit(limit).all()
    return {"inquiries": [service.admin_record(row) for row in rows], "total": total, "next_offset": offset + len(rows) if offset + len(rows) < total else None}


@router.get("/api/v1/admin/research-inquiries/{inquiry_id}")
def get_research_inquiry(inquiry_id: UUID, response: Response, db: Session = Depends(get_db), _admin=Depends(_require_platform_admin)):
    response.headers["Cache-Control"] = "no-store"
    row = db.query(ResearchInquiry).filter(ResearchInquiry.inquiry_id == str(inquiry_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inquiry not found")
    return {"inquiry": service.admin_record(row)}


@router.patch("/api/v1/admin/research-inquiries/{inquiry_id}")
def update_research_inquiry(inquiry_id: UUID, update: ResearchInquiryStatusUpdate, response: Response,
                            db: Session = Depends(get_db), _admin=Depends(_require_platform_admin)):
    response.headers["Cache-Control"] = "no-store"
    row = db.query(ResearchInquiry).filter(ResearchInquiry.inquiry_id == str(inquiry_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inquiry not found")
    try:
        service.change_status(db, row, update.status, int(_admin["sub"]))
    except Exception:
        db.rollback()
        return _error(503, "Inquiry status could not be updated")
    return {"inquiry_id": inquiry_id, "processing_status": row.processing_status}


@router.post("/api/v1/admin/research-inquiries/{inquiry_id}/notifications/retry")
def retry_research_inquiry_notification(inquiry_id: UUID, response: Response, db: Session = Depends(get_db), _admin=Depends(_require_platform_admin)):
    response.headers["Cache-Control"] = "no-store"
    row = db.query(ResearchInquiry).filter(ResearchInquiry.inquiry_id == str(inquiry_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Inquiry not found")
    if row.notification_status == "sent":
        raise HTTPException(status_code=409, detail="Notification already sent")
    try:
        sent = service.notify(db, row, actor_user_id=int(_admin["sub"]))
    except Exception:
        db.rollback()
        NOTIFICATIONS.labels("state_update_failed").inc()
        return _error(503, "Notification state unavailable")
    NOTIFICATIONS.labels("sent" if sent else row.notification_status).inc()
    if not sent:
        return _error(502 if row.notification_status == "failed" else 503, "Notification was not delivered")
    return {"inquiry_id": inquiry_id, "notification_status": "sent"}
