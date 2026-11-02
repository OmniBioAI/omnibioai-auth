"""Synthetic HTTP security, administration, and deterministic delivery coverage."""
import ipaddress
import json
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
import redis
from starlette.requests import Request

from app.api import routes_research_inquiries as routes
from app.core.config import settings
from app.core.jwt import create_access_token
from app.core import rate_limit
from app.db.models import AuditEvent, User
from app.db.research_inquiry import ResearchInquiry
from app.db.session import get_db
from app.main import app
from app.schemas.research_inquiry import ResearchInquiryCreate
from app.services import email_delivery_service
from tests.test_research_inquiries import payload, research_config  # noqa: F401

REAL_RATE_LIMIT = routes._rate_limit
PATH = "/api/v1/research-inquiries"
ADMIN = "/api/v1/admin/research-inquiries"


def session():
    return next(app.dependency_overrides[get_db]())


@pytest.fixture(autouse=True)
def local_delivery(monkeypatch):
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", Mock(return_value="local-test-receipt"))


@pytest.mark.parametrize("field", ["full_name", "institutional_email", "institution", "department", "country",
                                  "research_interest", "proposed_collaboration", "consent"])
def test_missing_required(client, field):
    data = payload()
    del data[field]
    assert client.post(PATH, json=data).status_code == 422


@pytest.mark.parametrize("changes", [
    {"institutional_email": ".name@example.edu"}, {"institutional_email": "a..b@example.edu"},
    {"institutional_email": "a<>b@example.edu"}, {"institutional_email": "a@example"},
    {"institutional_email": "a@example.edu\r\nBcc: x@example.edu"},
    {"institutional_website": "file:///etc/passwd"}, {"institutional_website": "https://127.0.0.1/x"},
    {"institutional_website": "https://user:secret@example.edu"},
    {"institutional_website": "https://example.edu:invalid"},
    {"institutional_website": "https://bad host.example.edu"},
    {"institutional_website": "https://example.edu\\@127.0.0.1"},
    {"consent": 1}, {"consent": "true"}, {"full_name": 123},
    {"full_name": "x" * 121}, {"proposed_collaboration": "x" * 4001},
    {"country": "United\x00States"}, {"full_name": "Name\r\nBcc: person@example.edu"},
    {"additional_information": "Bearer synthetic-secret"}, {"institution": "\ud800"},
    {"unexpected": "field"},
])
def test_strict_validation(client, changes):
    response = client.post(PATH, content=json.dumps(payload(**changes)), headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert "synthetic-secret" not in response.text


@pytest.mark.parametrize(("body", "media", "expected"), [
    (b"\xff", "application/json", 400), (b"{", "application/json", 400),
    (b"{}", "application/jsonp", 415), (b"{}", "text/plain", 415),
    (b"[]", "application/json", 422),
])
def test_wire_validation(client, body, media, expected):
    assert client.post(PATH, content=body, headers={"Content-Type": media}).status_code == expected


def test_streamed_size_limit(client):
    response = client.post(PATH, content=iter([b"x" * 9000, b"x" * 9000]),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_disallowed_origin_cannot_persist(client):
    assert client.post(PATH, json=payload(), headers={"Origin": "https://attacker.example"}).status_code == 403
    with session() as db:
        assert db.query(ResearchInquiry).count() == 0


@pytest.mark.parametrize(("peer", "trusted", "forwarded", "expected"), [
    ("192.0.2.1", (), "198.51.100.2", "192.0.2.1"),
    ("192.0.2.1", ("192.0.2.1/32",), "198.51.100.2", "198.51.100.2"),
    ("192.0.2.1", ("192.0.2.1/32",), "invalid", "unknown"),
    ("::1", ("::1/128",), "2001:db8::1", "2001:db8::1"),
])
def test_proxy_boundary(monkeypatch, peer, trusted, forwarded, expected):
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_TRUSTED_PROXIES", tuple(map(ipaddress.ip_network, trusted)))
    request = Request({"type": "http", "client": (peer, 80), "headers": [
        (b"cf-connecting-ip", forwarded.encode()), (b"x-forwarded-for", b"203.0.113.99")]})
    assert routes._client_address(request) == expected


def test_real_rate_limiter_and_ip_separation(client, monkeypatch):
    monkeypatch.setattr(routes, "_rate_limit", REAL_RATE_LIMIT)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_RATE_LIMIT", 2)
    # Invalid requests count too, before any database persistence.
    assert [client.post(PATH, json={}).status_code for _ in range(3)] == [422, 422, 429]
    request = Request({"type": "http", "client": ("198.51.100.7", 80), "headers": []})
    assert REAL_RATE_LIMIT(request) is None


def test_redis_outage_uses_bounded_fallback(client, monkeypatch):
    monkeypatch.setattr(routes, "_rate_limit", REAL_RATE_LIMIT)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_RATE_LIMIT", 2)
    monkeypatch.setattr(rate_limit, "_redis", Mock(ttl=Mock(side_effect=redis.ConnectionError),
                                                eval=Mock(side_effect=redis.ConnectionError)))
    assert [client.post(PATH, json={}).status_code for _ in range(3)] == [422, 422, 429]


def test_duplicate_normalization_and_day_boundary():
    initial = ResearchInquiryCreate.model_validate(payload(proposed_collaboration="Synthetic\r\nproposal"))
    normalized = ResearchInquiryCreate.model_validate(payload(proposed_collaboration="Synthetic\nproposal"))
    now = datetime(2026, 11, 2, 23, 59)
    fingerprint = routes.service.duplicate_fingerprint
    assert fingerprint(initial, now) == fingerprint(normalized, now)
    assert fingerprint(initial, now) != fingerprint(initial, now + timedelta(days=1))
    changed = ResearchInquiryCreate.model_validate(payload(full_name="Different person", proposed_collaboration="Synthetic\nproposal"))
    assert fingerprint(initial, now) != fingerprint(changed, now)


def test_missing_notification_configuration_still_persists(client, monkeypatch):
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_TO", "")
    response = client.post(PATH, json=payload())
    assert response.status_code == 201
    with session() as db:
        row = db.get(ResearchInquiry, response.json()["inquiry_id"])
        assert row.notification_status == "not_configured"
        assert row.notification_attempts == 0
    routes.service.send_research_inquiry_notification.assert_not_called()


def test_notification_state_exception_does_not_undo_receipt(client, monkeypatch):
    monkeypatch.setattr(routes.service, "notify", Mock(side_effect=RuntimeError("private db details")))
    response = client.post(PATH, json=payload())
    assert response.status_code == 201
    with session() as db:
        assert db.get(ResearchInquiry, response.json()["inquiry_id"]) is not None
    assert "private" not in response.text


@pytest.fixture
def admin_headers():
    with session() as db:
        user = db.query(User).filter_by(status="active").first()
        return {"Authorization": "Bearer " + create_access_token({
            "sub": str(user.id), "permissions": ["manage_all_orgs"], "type": "access"})}


def test_insufficient_permission_rejected(client):
    with session() as db:
        user = db.query(User).filter_by(status="active").first()
        token = create_access_token({"sub": str(user.id), "permissions": [], "type": "access"})
    assert client.get(ADMIN, headers={"Authorization": "Bearer " + token}).status_code == 403


def test_admin_review_pagination_status_and_audit(client, admin_headers):
    first = client.post(PATH, json=payload()).json()["inquiry_id"]
    second = client.post(PATH, json=payload(full_name="Synthetic second")).json()["inquiry_id"]
    response = client.get(ADMIN + "?limit=1", headers=admin_headers)
    assert response.status_code == 200 and response.json()["total"] == 2
    assert response.json()["next_offset"] == 1
    assert response.headers["cache-control"] == "no-store"
    records = response.json()["inquiries"] + client.get(ADMIN + "?limit=1&offset=1", headers=admin_headers).json()["inquiries"]
    assert {r["inquiry_id"] for r in records} == {first, second}
    assert all("duplicate_fingerprint" not in r for r in records)
    assert client.get(ADMIN + "/" + first, headers=admin_headers).json()["inquiry"]["full_name"] == "Synthetic Researcher"
    assert client.patch(ADMIN + "/" + first, json={"status": "in_review"}, headers=admin_headers).status_code == 200
    assert client.get(ADMIN + "?status=in_review", headers=admin_headers).json()["total"] == 1
    assert client.patch(ADMIN + "/" + first, json={"status": "unsupported"}, headers=admin_headers).status_code == 422
    with session() as db:
        event = db.query(AuditEvent).filter_by(event_type="research_inquiry_status_changed", resource_id=first).one()
        assert event.actor_user_id is not None and event.integrity_digest
        assert event.before_state == {"status": "new"} and event.after_state == {"status": "in_review"}


def test_admin_mutation_rollback_on_audit_failure(client, admin_headers, monkeypatch):
    inquiry_id = client.post(PATH, json=payload()).json()["inquiry_id"]
    monkeypatch.setattr(routes.service, "log_event", Mock(side_effect=RuntimeError("synthetic audit failure")))
    assert client.patch(ADMIN + "/" + inquiry_id, json={"status": "closed"}, headers=admin_headers).status_code == 503
    with session() as db:
        assert db.get(ResearchInquiry, inquiry_id).processing_status == "new"


def test_notification_retries_are_bounded_authorized_and_audited(client, admin_headers, monkeypatch):
    sender = Mock(side_effect=routes.service.EmailDeliveryError("synthetic failure"))
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", sender)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_MAX_ATTEMPTS", 2)
    inquiry_id = client.post(PATH, json=payload()).json()["inquiry_id"]
    retry = ADMIN + "/" + inquiry_id + "/notifications/retry"
    assert client.post(retry).status_code in {401, 403}
    assert client.post(retry, headers=admin_headers).status_code == 502
    assert client.post(retry, headers=admin_headers).status_code == 502
    assert sender.call_count == 2
    with session() as db:
        row = db.get(ResearchInquiry, inquiry_id)
        assert row.notification_attempts == 2 and row.notification_last_error == "retry_exhausted"
        assert db.query(AuditEvent).filter_by(event_type="research_inquiry_notification_retry", resource_id=inquiry_id).count() == 1


def test_sent_notification_cannot_be_retried(client, admin_headers):
    inquiry_id = client.post(PATH, json=payload()).json()["inquiry_id"]
    assert client.post(ADMIN + "/" + inquiry_id + "/notifications/retry", headers=admin_headers).status_code == 409
    assert routes.service.send_research_inquiry_notification.call_count == 1


def test_provider_key_stable_and_notification_minimized(monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_SERVICE_SEND_URL", "https://delivery.example.test/send")
    monkeypatch.setattr(settings, "EMAIL_SERVICE_TOKEN", "synthetic-token")
    transport = Mock(return_value=Mock(raise_for_status=Mock(), json=Mock(return_value={"id": "receipt"})))
    monkeypatch.setattr(email_delivery_service.httpx, "post", transport)
    for _ in range(2):
        email_delivery_service.send_research_inquiry_notification("authorized@example.org",
            inquiry_id="00000000-0000-4000-8000-000000000001", full_name="Synthetic Researcher",
            institutional_email="researcher@example.edu", institution="Example University", department="Test",
            country="Test", research_interest="multi_omics")
    calls = transport.call_args_list
    assert calls[0].kwargs["headers"]["Idempotency-Key"] == calls[1].kwargs["headers"]["Idempotency-Key"]
    assert "researcher@example.edu" not in calls[0].kwargs["json"]["text"]


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_no_public_record_lookup(client, method):
    assert client.request(method, PATH).status_code == 405
