"""Synthetic-only coverage for public inquiry persistence and administration."""

import uuid

import pytest

from app.api import routes_research_inquiries as routes
from app.core.config import settings
from app.db.research_inquiry import ResearchInquiry
from app.db.session import get_db
from app.main import app


def payload(**changes):
    value = {
        "full_name": "Synthetic Researcher",
        "institutional_email": "researcher@example.edu",
        "institution": "Example University",
        "department": "Computational Biology",
        "country": "United States",
        "research_interest": "multi_omics",
        "proposed_collaboration": "Evaluate a synthetic benchmark with reproducible methods.",
        "potential_datasets": "Synthetic non-identifiable data only.",
        "institutional_website": "https://www.example.edu/research",
        "additional_information": "No sensitive data is included.",
        "consent": True,
        "company_fax": "",
    }
    value.update(changes)
    return value


@pytest.fixture(autouse=True)
def research_config(monkeypatch, client):
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_ENABLED", True)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_HMAC_KEY", "synthetic-research-inquiry-key-32-bytes-minimum")
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_TO", "authorized@example.org")
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_NOTIFICATION_IDEMPOTENCY_CONFIRMED", True)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_RATE_LIMIT", 50)
    monkeypatch.setattr(settings, "RESEARCH_INQUIRY_TRUSTED_PROXIES", ())
    monkeypatch.setattr(routes, "_rate_limit", lambda _request: None)
    db = next(app.dependency_overrides[get_db]())
    try:
        db.query(ResearchInquiry).delete()
        db.commit()
    finally:
        db.close()
    yield


def test_valid_submission_persists_and_returns_same_id(client, monkeypatch):
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", lambda *args, **kwargs: "synthetic-receipt")
    response = client.post("/api/v1/research-inquiries", json=payload())
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "received"
    uuid.UUID(body["inquiry_id"])
    db = next(app.dependency_overrides[get_db]())
    try:
        row = db.query(ResearchInquiry).filter_by(inquiry_id=body["inquiry_id"]).one()
        assert row.inquiry_id == body["inquiry_id"]
        assert row.notification_status == "sent"
        assert row.consent_timestamp == row.submission_timestamp
        assert row.processing_status == "new"
    finally:
        db.close()


@pytest.mark.parametrize(("changes", "field"), [
    ({"full_name": ""}, "full_name"),
    ({"institutional_email": "person@gmail.com"}, "institutional_email"),
    ({"institutional_website": "javascript:alert(1)"}, "institutional_website"),
    ({"consent": False}, "consent"),
    ({"research_interest": "uncontrolled"}, "research_interest"),
    ({"additional_information": "api_key=synthetic-secret"}, "additional_information"),
])
def test_validation_rejects_invalid_fields(client, changes, field):
    response = client.post("/api/v1/research-inquiries", json=payload(**changes))
    assert response.status_code == 422
    assert field in response.json()["field_errors"]


def test_malformed_oversized_and_honeypot(client):
    malformed = client.post("/api/v1/research-inquiries", content="{", headers={"Content-Type": "application/json"})
    assert malformed.status_code == 400
    oversized = client.post("/api/v1/research-inquiries", content=b"x" * 17000, headers={"Content-Type": "application/json"})
    assert oversized.status_code == 413
    honeypot = client.post("/api/v1/research-inquiries", json=payload(company_fax="bot"))
    assert honeypot.status_code == 204


def test_duplicate_is_rejected(client, monkeypatch):
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", lambda *args, **kwargs: "synthetic-receipt")
    first = client.post("/api/v1/research-inquiries", json=payload())
    second = client.post("/api/v1/research-inquiries", json=payload())
    assert first.status_code == 201
    assert second.status_code == 409


def test_database_failure_never_returns_success(client, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic database failure")
    monkeypatch.setattr(routes.service, "create", fail)
    assert client.post("/api/v1/research-inquiries", json=payload()).status_code == 503


def test_notification_failure_is_persisted_without_false_submission_failure(client, monkeypatch):
    def fail(*args, **kwargs):
        raise routes.service.EmailDeliveryError("synthetic delivery failure")
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", fail)
    response = client.post("/api/v1/research-inquiries", json=payload())
    assert response.status_code == 201
    db = next(app.dependency_overrides[get_db]())
    try:
        row = db.query(ResearchInquiry).filter_by(inquiry_id=response.json()["inquiry_id"]).one()
        assert row.notification_status == "failed"
        assert row.notification_last_error == "delivery_failed"
    finally:
        db.close()


def test_admin_routes_reject_unauthorized_and_allow_permission_dependency(client, monkeypatch):
    assert client.get("/api/v1/admin/research-inquiries").status_code in {401, 403}
    app.dependency_overrides[routes._require_platform_admin] = lambda: {"permissions": ["manage_all_orgs"]}
    try:
        response = client.get("/api/v1/admin/research-inquiries")
        assert response.status_code == 200
        assert "inquiries" in response.json()
    finally:
        app.dependency_overrides.pop(routes._require_platform_admin, None)


def test_cors_restricts_origins(client):
    denied = client.options("/api/v1/research-inquiries", headers={"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST"})
    assert denied.status_code == 400
    assert denied.headers.get("access-control-allow-origin") is None
    allowed = client.options("/api/v1/research-inquiries", headers={"Origin": "https://omnibioai.org", "Access-Control-Request-Method": "POST"})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://omnibioai.org"


def test_rate_limit_rejects_without_entering_persistence(client, monkeypatch):
    monkeypatch.setattr(routes, "_rate_limit", lambda _request: routes._error(429, "Too many requests", headers={"Retry-After": "60"}))
    response = client.post("/api/v1/research-inquiries", json=payload())
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"


def test_sql_and_xss_shapes_remain_inert_parameterized_data(client, monkeypatch):
    monkeypatch.setattr(routes.service, "send_research_inquiry_notification", lambda *args, **kwargs: "synthetic-receipt")
    name = "Synthetic'; DROP TABLE research_inquiries;--"
    proposal = '<script>alert("synthetic")</script> evaluate safely'
    response = client.post("/api/v1/research-inquiries", json=payload(full_name=name, proposed_collaboration=proposal))
    assert response.status_code == 201
    db = next(app.dependency_overrides[get_db]())
    try:
        row = db.query(ResearchInquiry).filter_by(inquiry_id=response.json()["inquiry_id"]).one()
        assert row.full_name == name
        assert row.proposed_collaboration == proposal
        assert db.query(ResearchInquiry).count() >= 1
    finally:
        db.close()
