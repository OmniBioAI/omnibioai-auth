"""HIPAA Phase 1 PR1: local-password login brute-force / abuse protection.

Exercises app/core/rate_limit.py + app/services/login_throttle_service.py
through both the real HTTP surface (POST /auth/login) and, where HTTP
alone can't isolate one dimension cleanly, direct calls to the service
layer. See login_throttle_service.py's module docstring for what each of
the account/ip/pair dimensions defends against.

Multiple simulated source IPs are exercised via separate
`TestClient(app, client=(ip, port))` instances wrapping the SAME `app`
singleton the session-scoped `client` fixture already configured
(dependency_overrides + the fakeredis/blacklist/pub patches all live on
that shared `app` object and the patched module attributes, not on any
one TestClient instance), rather than trying to spoof
`request.client.host` some other way.
"""
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from app.core import rate_limit
from app.core.config import settings
from app.db.models import AuditEvent
from app.main import app
from app.services import login_throttle_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _unique_email():
    return f"ratelimit-{uuid.uuid4().hex[:10]}@omnibioai.test"


def _register(client, email, password="TestPassword123!"):
    resp = client.post("/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 200
    return {"email": email, "password": password}


def _client_at(ip: str) -> TestClient:
    """A second TestClient wrapping the same `app` -- see module
    docstring. Not used as a context manager: app.main has no ASGI
    lifespan/startup events, so a plain instance is sufficient for
    request/response testing.
    """
    return TestClient(app, client=(ip, 51000))


def _rate_limit_events(email: str | None = None):
    db = _DirectSession()
    try:
        q = db.query(AuditEvent).filter(AuditEvent.event_type == "auth_rate_limit_triggered")
        events = q.all()
        if email is not None:
            events = [e for e in events if e.event_metadata.get("email") == email]
        return events
    finally:
        db.close()


@pytest.fixture
def tight_limits(monkeypatch):
    """Small, fast, deterministic thresholds -- production defaults
    (config.py) are covered by asserting the config wiring itself
    (test_config-style), not by running dozens of real HTTP round trips
    per test. Keeps PAIR < ACCOUNT < IP, matching the real relationship
    (see login_throttle_service.py's module docstring for why).
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 4)
    monkeypatch.setattr(settings, "RATE_LIMIT_ACCOUNT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_IP_MAX_ATTEMPTS", 8)
    monkeypatch.setattr(settings, "RATE_LIMIT_IP_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_IP_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_PROGRESSIVE_MULTIPLIER", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_MAX_LOCKOUT_SECONDS", 20)
    monkeypatch.setattr(settings, "RATE_LIMIT_STRIKE_TTL_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_FALLBACK_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_FALLBACK_WINDOW_SECONDS", 60)


# ── Normal authentication ────────────────────────────────────────────────

def test_valid_credentials_succeed(client, tight_limits):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json=user)
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body and "refresh_token" in body


def test_single_invalid_password_fails_normally(client, tight_limits):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json={"email": user["email"], "password": "wrong"})
    assert resp.status_code == 401


def test_unknown_user_fails_same_as_wrong_password(client, tight_limits):
    known = _register(client, _unique_email())
    wrong_pw = client.post("/auth/login", json={"email": known["email"], "password": "wrong"})
    unknown = client.post("/auth/login", json={"email": _unique_email(), "password": "anything"})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_successful_login_issues_normal_tokens(client, tight_limits):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json=user)
    body = resp.json()
    assert body["token_type"] == "bearer"
    validate = client.post("/auth/validate", json={"token": body["access_token"]})
    assert validate.json()["valid"] is True


# ── Account-based throttling ─────────────────────────────────────────────

def test_account_locked_after_max_attempts_across_different_ips(client, tight_limits):
    user = _register(client, _unique_email())
    # Each IP stays well under its own IP/pair thresholds (max_attempts-1
    # per IP), so only the account dimension can be what locks this. The
    # Nth failure is the one that *crosses* the threshold and sets the
    # lock -- it still gets a normal 401 itself (the lock wasn't set yet
    # when this request was checked); it's the (N+1)th that gets 429.
    responses = []
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        c = _client_at(f"10.0.0.{i}")
        responses.append(c.post("/auth/login", json={"email": user["email"], "password": "wrong"}))
    assert [r.status_code for r in responses[:-1]] == [401] * (len(responses) - 1)
    assert responses[-1].status_code == 429


def test_account_lockout_blocks_even_the_correct_password(client, tight_limits):
    user = _register(client, _unique_email())
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS):
        c = _client_at(f"10.0.1.{i}")
        c.post("/auth/login", json={"email": user["email"], "password": "wrong"})
    # Locked now -- even the real password must not succeed while locked.
    resp = _client_at("10.0.1.200").post("/auth/login", json=user)
    assert resp.status_code == 429


def test_account_lockout_expires_after_window(client, tight_limits):
    user = _register(client, _unique_email())
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS):
        c = _client_at(f"10.0.2.{i}")
        c.post("/auth/login", json={"email": user["email"], "password": "wrong"})
    locked = _client_at("10.0.2.200").post("/auth/login", json=user)
    assert locked.status_code == 429

    time.sleep(settings.RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS + 0.5)
    recovered = _client_at("10.0.2.201").post("/auth/login", json=user)
    assert recovered.status_code == 200


def test_successful_login_resets_account_failure_counter(client, tight_limits):
    user = _register(client, _unique_email())
    # One under the threshold, from distinct IPs so the pair/ip counters
    # don't confound this.
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS - 1):
        c = _client_at(f"10.0.3.{i}")
        c.post("/auth/login", json={"email": user["email"], "password": "wrong"})

    success = _client_at("10.0.3.200").post("/auth/login", json=user)
    assert success.status_code == 200

    # A fresh batch, still one under threshold -- if the counter hadn't
    # reset, this would push the account over the line and lock it.
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS - 1):
        c = _client_at(f"10.0.4.{i}")
        resp = c.post("/auth/login", json={"email": user["email"], "password": "wrong"})
        assert resp.status_code == 401

    still_ok = _client_at("10.0.4.200").post("/auth/login", json=user)
    assert still_ok.status_code == 200


# ── IP-based protection ───────────────────────────────────────────────────

def test_ip_locked_after_many_failures_across_different_accounts(client, tight_limits):
    attacker = _client_at("203.0.113.9")
    responses = [
        attacker.post("/auth/login", json={"email": _unique_email(), "password": "guess"})
        for _ in range(settings.RATE_LIMIT_IP_MAX_ATTEMPTS + 1)
    ]
    assert responses[-1].status_code == 429
    assert all(r.status_code == 401 for r in responses[:-1])


def test_changing_account_does_not_bypass_ip_limit(client, tight_limits):
    """Security/bypass test: an attacker who only ever varies the target
    email, never the IP, must still eventually be stopped."""
    attacker = _client_at("203.0.113.10")
    last = None
    for _ in range(settings.RATE_LIMIT_IP_MAX_ATTEMPTS + 1):
        last = attacker.post("/auth/login", json={"email": _unique_email(), "password": "guess"})
    assert last.status_code == 429


# ── (account, IP) pair dimension ──────────────────────────────────────────

def test_pair_locks_faster_than_account_or_ip_alone(client, tight_limits):
    assert settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS < settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS
    assert settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS < settings.RATE_LIMIT_IP_MAX_ATTEMPTS

    user = _register(client, _unique_email())
    c = _client_at("198.51.100.5")
    responses = [
        c.post("/auth/login", json={"email": user["email"], "password": "wrong"})
        for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 1)
    ]
    assert responses[-1].status_code == 429


def test_bypass_attempt_changing_only_ip_still_bounded_by_account(client, tight_limits):
    """Security/bypass test: changing only the source IP (never the
    account) resets the pair/ip keys each time but must not reset the
    account key -- covered precisely by
    test_account_locked_after_max_attempts_across_different_ips above;
    this test additionally confirms it end-to-end through a *different*
    IP than any previously used, i.e. a truly fresh pair/ip key, still
    gets rejected once the account itself is locked."""
    user = _register(client, _unique_email())
    for i in range(settings.RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS):
        _client_at(f"172.16.5.{i}").post("/auth/login", json={"email": user["email"], "password": "wrong"})
    brand_new_ip = _client_at("172.16.99.99")
    resp = brand_new_ip.post("/auth/login", json=user)
    assert resp.status_code == 429


# ── Distributed / race behavior ────────────────────────────────────────────

def test_concurrent_failures_are_atomic_no_overshoot(client, tight_limits):
    """Fires many concurrent record_attempt calls at the same key pair
    directly against app/core/rate_limit.py -- the atomic Lua script is
    what this is actually testing, HTTP round trips would just add
    unrelated latency noise. Exactly one caller may observe
    newly_locked=True; the counter must never be incremented past what
    the actual number of calls justifies.
    """
    fail_key, lock_key = "ratelimit:test:concurrent:fail", "ratelimit:test:concurrent:lock"
    n_calls = 25
    max_attempts = 5

    def _attempt(_):
        return rate_limit.record_attempt(fail_key, lock_key, window_seconds=60,
                                          max_attempts=max_attempts, lockout_seconds=5)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_attempt, range(n_calls)))

    newly_locked = [r for r in results if r.newly_locked]
    assert len(newly_locked) == 1
    assert all(r.count <= n_calls for r in results)
    assert max(r.count for r in results) <= n_calls


def test_concurrent_requests_do_not_double_trigger_audit(client, tight_limits):
    user = _register(client, _unique_email())
    ip = "192.0.2.50"

    def _attempt(_):
        return _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(_attempt, range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5)))

    events = _rate_limit_events(user["email"])
    pair_events = [e for e in events if e.event_metadata.get("dimension") == "pair"]
    assert len(pair_events) == 1


# ── Reset / recovery behavior ──────────────────────────────────────────────

def test_expired_window_starts_fresh_without_locking(client, tight_limits):
    user = _register(client, _unique_email())
    ip = "192.0.2.77"
    for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS - 1):
        resp = _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})
        assert resp.status_code == 401

    # Let the pair lockout key's own window pass without ever crossing
    # the threshold -- next attempt should still be a normal 401, not
    # accumulate onto a stale window.
    time.sleep(settings.RATE_LIMIT_PAIR_LOCKOUT_SECONDS + 0.5)
    resp = _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})
    assert resp.status_code == 401


# ── Redis failure behavior ──────────────────────────────────────────────────

def test_redis_unavailable_falls_back_and_still_throttles(client, tight_limits, monkeypatch):
    class _Broken:
        def __getattr__(self, name):
            raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(rate_limit, "_redis", _Broken())
    user = _register(client, _unique_email())
    ip = "192.0.2.99"

    responses = [
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})
        for _ in range(settings.RATE_LIMIT_FALLBACK_MAX_ATTEMPTS + 2)
    ]
    # Not fail-open: still throttles once the (tighter) fallback
    # threshold is crossed.
    assert responses[-1].status_code == 429
    # Not fail-closed either: the attempts within the fallback budget
    # were processed as normal 401s, not blocked outright.
    assert responses[0].status_code == 401


def test_redis_unavailable_does_not_break_normal_login(client, tight_limits, monkeypatch):
    class _Broken:
        def __getattr__(self, name):
            raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(rate_limit, "_redis", _Broken())
    user = _register(client, _unique_email())
    resp = _client_at("192.0.2.100").post("/auth/login", json=user)
    assert resp.status_code == 200


def test_redis_recovery_uses_normal_thresholds_again(client, tight_limits, monkeypatch):
    class _Broken:
        def __getattr__(self, name):
            raise ConnectionError("simulated redis outage")

    real_redis = rate_limit._redis
    monkeypatch.setattr(rate_limit, "_redis", _Broken())
    user = _register(client, _unique_email())
    ip = "192.0.2.101"
    for _ in range(settings.RATE_LIMIT_FALLBACK_MAX_ATTEMPTS):
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})

    monkeypatch.setattr(rate_limit, "_redis", real_redis)
    # Redis is back -- a fresh IP/account pair should authenticate
    # normally again (the fallback state doesn't leak into or block the
    # Redis-backed path).
    resp = _client_at("192.0.2.102").post("/auth/login", json=user)
    assert resp.status_code == 200


# ── Audit ────────────────────────────────────────────────────────────────

def test_normal_failure_still_emits_login_failure_event(client, tight_limits):
    user = _register(client, _unique_email())
    db = _DirectSession()
    try:
        before = db.query(AuditEvent).filter(AuditEvent.event_type == "login_failure").count()
    finally:
        db.close()

    client.post("/auth/login", json={"email": user["email"], "password": "wrong"})

    db = _DirectSession()
    try:
        after = db.query(AuditEvent).filter(AuditEvent.event_type == "login_failure").count()
    finally:
        db.close()
    assert after == before + 1


def test_successful_login_still_emits_login_success_event(client, tight_limits):
    user = _register(client, _unique_email())
    db = _DirectSession()
    try:
        before = db.query(AuditEvent).filter(AuditEvent.event_type == "login_success").count()
    finally:
        db.close()

    client.post("/auth/login", json=user)

    db = _DirectSession()
    try:
        after = db.query(AuditEvent).filter(AuditEvent.event_type == "login_success").count()
    finally:
        db.close()
    assert after == before + 1


def test_rate_limit_trigger_emits_audit_event_with_expected_fields(client, tight_limits):
    user = _register(client, _unique_email())
    ip = "192.0.2.150"
    for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS):
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})

    events = _rate_limit_events(user["email"])
    pair_events = [e for e in events if e.event_metadata.get("dimension") == "pair"]
    assert len(pair_events) == 1
    meta = pair_events[0].event_metadata
    assert meta["email"] == user["email"]
    assert meta["ip"] == ip
    assert meta["lockout_seconds"] == settings.RATE_LIMIT_PAIR_LOCKOUT_SECONDS


def test_audit_events_never_contain_password_or_tokens(client, tight_limits):
    user = _register(client, _unique_email())
    ip = "192.0.2.151"
    for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS):
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "S3cretPassword!"})

    events = _rate_limit_events(user["email"])
    for e in events:
        blob = str(e.event_metadata)
        assert "S3cretPassword!" not in blob
        assert "access_token" not in blob
        assert "refresh_token" not in blob


def test_no_duplicate_audit_events_while_lockout_still_active(client, tight_limits):
    user = _register(client, _unique_email())
    ip = "192.0.2.152"
    for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 4):
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})

    events = _rate_limit_events(user["email"])
    pair_events = [e for e in events if e.event_metadata.get("dimension") == "pair"]
    assert len(pair_events) == 1


# ── Enumeration resistance ─────────────────────────────────────────────────

def test_throttled_response_identical_for_real_and_fake_accounts(client, tight_limits):
    real_user = _register(client, _unique_email())
    fake_email = _unique_email()

    real_ip = _client_at("198.18.0.1")
    fake_ip = _client_at("198.18.0.2")

    real_last = None
    fake_last = None
    for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 1):
        real_last = real_ip.post("/auth/login", json={"email": real_user["email"], "password": "wrong"})
        fake_last = fake_ip.post("/auth/login", json={"email": fake_email, "password": "wrong"})

    assert real_last.status_code == fake_last.status_code == 429
    assert real_last.json() == fake_last.json()
    assert real_last.headers.get("retry-after") is not None
    assert fake_last.headers.get("retry-after") is not None


# ── SSO exclusion ──────────────────────────────────────────────────────────

def test_sso_enforced_login_bypasses_password_throttle_entirely(client, tight_limits, monkeypatch):
    db = _DirectSession()
    try:
        org_id = db.execute(
            __import__("sqlalchemy").text("SELECT id FROM organizations LIMIT 1")
        ).scalar()
    finally:
        db.close()
    assert org_id is not None

    class _FakeEnforcedConfig:
        organization_id = org_id

    import app.api.routes_auth as routes_auth_module
    monkeypatch.setattr(
        routes_auth_module.sso_discovery_service,
        "find_enforced_org_for_email",
        lambda db, email: _FakeEnforcedConfig(),
    )

    sso_email = _unique_email()
    ip = "203.0.113.55"
    responses = [
        _client_at(ip).post("/auth/login", json={"email": sso_email, "password": "wrong"})
        for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5)
    ]
    assert all(r.status_code == 403 for r in responses)
    assert all(r.json()["detail"]["reason"] == "sso_required" for r in responses)

    locked, _ = rate_limit.is_locked(f"{login_throttle_service._account_key(sso_email)}:lock")
    assert locked is False


# ── Malformed / adversarial requests ────────────────────────────────────────

def test_malformed_login_request_returns_validation_error_not_crash(client, tight_limits):
    resp = client.post("/auth/login", json={"email": "missing-password@omnibioai.test"})
    assert resp.status_code == 422


def test_very_long_password_handled_safely(client, tight_limits):
    """Discovery finding fixed alongside this PR: passlib's bcrypt
    handler raises PasswordSizeError (not a plain boolean False) for a
    password over its own 4096-byte cap -- previously uncaught in
    app/core/security.py::verify_password, so this exact request used to
    500 instead of returning the normal 401 every other wrong-password
    case gets. See that module's updated docstring.
    """
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json={"email": user["email"], "password": "x" * 10000})
    assert resp.status_code == 401


def test_very_long_email_handled_safely(client, tight_limits):
    long_email = "a" * 5000 + "@omnibioai.test"
    resp = client.post("/auth/login", json={"email": long_email, "password": "whatever"})
    assert resp.status_code in (401, 422)


def test_spoofed_forwarded_for_header_does_not_change_effective_ip(client, tight_limits):
    """This service derives the client IP from the ASGI transport
    (request.client.host), not from any client-suppliable header -- a
    spoofed X-Forwarded-For claiming a different IP on every request
    must not let an attacker reset the IP-dimension counter."""
    c = _client_at("209.0.113.1")
    last = None
    for i in range(settings.RATE_LIMIT_IP_MAX_ATTEMPTS + 1):
        last = c.post(
            "/auth/login",
            json={"email": _unique_email(), "password": "guess"},
            headers={"X-Forwarded-For": f"1.2.3.{i}"},
        )
    assert last.status_code == 429


# ── Config wiring sanity ────────────────────────────────────────────────────

def test_rate_limiting_disableable_via_settings(client, tight_limits, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    user = _register(client, _unique_email())
    ip = "198.18.9.9"
    responses = [
        _client_at(ip).post("/auth/login", json={"email": user["email"], "password": "wrong"})
        for _ in range(settings.RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5)
    ]
    assert all(r.status_code == 401 for r in responses)
