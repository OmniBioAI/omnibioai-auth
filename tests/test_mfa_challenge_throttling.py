"""HIPAA Phase 3: MFA/TOTP challenge brute-force protection.

Exercises app/services/mfa_throttle_service.py through the real HTTP
surface (POST /users/me/mfa/challenge), following this repo's established
convention for its sibling
tests/test_login_rate_limiting.py/tests/test_mfa_login_challenge.py: real
routes/services against the shared sqlite test DB, rows/audit events read
back via a second, direct session. Self-contained (local helpers), same
per-file duplication convention every other test file here already uses.
"""
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

from app.core import rate_limit
from app.core.config import settings
from app.db.models import AuditEvent, User
from app.main import app
from app.services import mfa_service, mfa_throttle_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"mfa-throttle-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _client_at(ip: str) -> TestClient:
    """A second TestClient wrapping the same `app` -- see
    tests/test_login_rate_limiting.py's module docstring for why this,
    not some other way of spoofing request.client.host, is this repo's
    established technique."""
    return TestClient(app, client=(ip, 51000))


def _enable_mfa(client, headers) -> str:
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


def _fresh_challenge_token(client, user) -> str:
    """Every test below needs a *currently valid* challenge_token --
    failed verification does NOT consume one (only a successful
    verification does, see mfa_service._consume_challenge_jti), so
    ordinarily a single token would suffice for many wrong-code attempts
    within its own 5-minute TTL. Fetching a fresh one per attempt instead
    verifies the throttle catches the (arguably worse, since it doesn't
    even require the code-guessing token itself to be reused) case of an
    attacker re-authenticating with the password each time too."""
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    return resp.json()["challenge_token"]


def _events(**filters) -> list[dict]:
    db = _DirectSession()
    try:
        query = db.query(AuditEvent)
        for key, value in filters.items():
            query = query.filter(getattr(AuditEvent, key) == value)
        rows = query.order_by(AuditEvent.id).all()
        return [
            {
                "id": r.id, "event_type": r.event_type, "actor_user_id": r.actor_user_id,
                "target_user_id": r.target_user_id, "organization_id": r.organization_id,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _user_row(user_id: int) -> User:
    db = _DirectSession()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_mfa.py's/tests/test_mfa_login_challenge.py's
    fixture of the same name."""
    import app.core.crypto as crypto
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def mfa_user(client, configured_crypto):
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    user["secret"] = _enable_mfa(client, headers)
    user["user_id"] = _user_id(client, user["access_token"])
    return user


@pytest.fixture
def tight_limits(monkeypatch):
    """Small, fast, deterministic thresholds -- production defaults
    (config.py) are covered by asserting the config wiring itself, not by
    running dozens of real HTTP round trips per test. Keeps
    PAIR < ACCOUNT < IP, matching the real relationship (see
    mfa_throttle_service.py's module docstring)."""
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 4)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_IP_MAX_ATTEMPTS", 8)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_IP_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_IP_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_PAIR_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS", 2)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_PROGRESSIVE_MULTIPLIER", 2)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_MAX_LOCKOUT_SECONDS", 20)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_STRIKE_TTL_SECONDS", 60)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS", 60)


def _wrong_code(correct: str) -> str:
    return ("1" if correct[0] != "1" else "2") + correct[1:]


# ── Baseline: existing MFA/non-MFA flows unaffected ─────────────────────────


def test_existing_valid_mfa_flow_still_succeeds(client, mfa_user, tight_limits):
    token = _fresh_challenge_token(client, mfa_user)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_existing_non_mfa_login_unchanged(client, tight_limits):
    user = _register_and_login(client)
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    assert "mfa_required" not in resp.json()


# ── First/repeated failures ──────────────────────────────────────────────


def test_first_failed_totp_attempt_is_counted(client, mfa_user, tight_limits):
    correct = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    token = _fresh_challenge_token(client, mfa_user)
    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": _wrong_code(correct)})
    assert resp.status_code == 400

    locked, _ = rate_limit.is_locked(f"{mfa_throttle_service._account_key(mfa_user['user_id'])}:lock")
    assert locked is False  # one failure alone must not lock the account
    events = _events(event_type="mfa_verification_failed", actor_user_id=mfa_user["user_id"])
    assert len(events) == 1


def test_repeated_failed_attempts_eventually_throttle(client, mfa_user, tight_limits):
    correct = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    wrong = _wrong_code(correct)

    # Uses the shared `client` fixture's one fixed source IP for every
    # attempt -- deliberately dimension-agnostic (unlike the account/pair/
    # ip-specific tests below, which control IP precisely to isolate one
    # dimension): with a constant IP, the (account, IP) pair dimension
    # (tighter threshold) trips before the account dimension alone would,
    # same as production behavior. This test only asserts the end-to-end
    # outcome -- first failure never locks, repeated failures eventually
    # do -- not which dimension gets there first.
    responses = []
    for _ in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(client, mfa_user)
        responses.append(client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}))

    assert responses[0].status_code == 400
    assert responses[-1].status_code == 429
    assert 200 not in [r.status_code for r in responses]


# ── Account dimension ─────────────────────────────────────────────────────


def test_account_locked_after_max_attempts_across_different_ips(client, mfa_user, tight_limits):
    correct = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    wrong = _wrong_code(correct)

    responses = []
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        # Each IP stays under its own IP/pair thresholds (max_attempts-1
        # per IP) so only the account dimension can be what locks this.
        resp = _client_at(f"10.10.0.{i}").post(
            "/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]}
        )
        token = resp.json()["challenge_token"]
        responses.append(
            _client_at(f"10.10.0.{i}").post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})
        )
    assert [r.status_code for r in responses[:-1]] == [400] * (len(responses) - 1)
    assert responses[-1].status_code == 429


def test_account_lockout_blocks_even_the_correct_code(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS):
        token = _fresh_challenge_token(_client_at(f"10.10.1.{i}"), mfa_user)
        _client_at(f"10.10.1.{i}").post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    # Locked now -- even the real code must not succeed while locked.
    token = _fresh_challenge_token(_client_at("10.10.1.200"), mfa_user)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    resp = _client_at("10.10.1.200").post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert resp.status_code == 429


def test_account_lockout_expires_after_window(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS):
        token = _fresh_challenge_token(_client_at(f"10.10.2.{i}"), mfa_user)
        _client_at(f"10.10.2.{i}").post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    locked_token = _fresh_challenge_token(_client_at("10.10.2.200"), mfa_user)
    locked = _client_at("10.10.2.200").post(
        "/users/me/mfa/challenge", json={"challenge_token": locked_token, "code": wrong}
    )
    assert locked.status_code == 429

    time.sleep(settings.MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS + 0.5)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    recovered_token = _fresh_challenge_token(_client_at("10.10.2.201"), mfa_user)
    recovered = _client_at("10.10.2.201").post(
        "/users/me/mfa/challenge", json={"challenge_token": recovered_token, "code": code}
    )
    assert recovered.status_code == 200


# ── IP dimension ──────────────────────────────────────────────────────────


def test_ip_locked_after_many_failures_across_different_accounts(client, configured_crypto, tight_limits):
    attacker = _client_at("203.0.113.77")
    users = []
    for _ in range(settings.MFA_RATE_LIMIT_IP_MAX_ATTEMPTS + 1):
        u = _register_and_login(client)
        headers = _auth_header(u["access_token"])
        u["secret"] = _enable_mfa(client, headers)
        users.append(u)

    responses = []
    for u in users:
        token = _fresh_challenge_token(attacker, u)
        wrong = _wrong_code(mfa_service._totp_code_at(u["secret"], int(time.time())))
        responses.append(attacker.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}))

    assert responses[-1].status_code == 429
    assert all(r.status_code == 400 for r in responses[:-1])


# ── (account, IP) pair dimension ────────────────────────────────────────────


def test_pair_locks_faster_than_account_or_ip_alone(client, mfa_user, tight_limits):
    assert settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS < settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS
    assert settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS < settings.MFA_RATE_LIMIT_IP_MAX_ATTEMPTS

    c = _client_at("198.51.100.44")
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    responses = []
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(c, mfa_user)
        responses.append(c.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}))
    assert responses[-1].status_code == 429


# ── Successful verification resets state ────────────────────────────────────


def test_successful_verification_resets_account_failure_counter(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS - 1):
        token = _fresh_challenge_token(_client_at(f"10.10.3.{i}"), mfa_user)
        resp = _client_at(f"10.10.3.{i}").post(
            "/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}
        )
        assert resp.status_code == 400

    good_token = _fresh_challenge_token(_client_at("10.10.3.200"), mfa_user)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    success = _client_at("10.10.3.200").post(
        "/users/me/mfa/challenge", json={"challenge_token": good_token, "code": code}
    )
    assert success.status_code == 200

    # A fresh batch, still one under threshold -- if the counter hadn't
    # reset, this would push the account over the line.
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS - 1):
        token = _fresh_challenge_token(_client_at(f"10.10.4.{i}"), mfa_user)
        resp = _client_at(f"10.10.4.{i}").post(
            "/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}
        )
        assert resp.status_code == 400


def test_throttled_account_cannot_continue_unlimited_attempts(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.5.1"
    statuses = []
    for _ in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 5):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        statuses.append(_client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}).status_code)

    # Once locked, every further attempt in this run stays 429 -- never
    # reverts to 400 while the lockout is still active.
    first_429 = statuses.index(429)
    assert all(s == 429 for s in statuses[first_429:])


# ── Retry-After / response shape ────────────────────────────────────────────


def test_429_response_has_retry_after_and_generic_body(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.6.1"
    last = None
    for _ in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        last = _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    assert last.status_code == 429
    assert last.headers.get("retry-after") is not None
    assert int(last.headers["retry-after"]) > 0
    body = last.json()
    assert body["error"] == "too_many_attempts"
    # Never the internal counter or the configured threshold.
    assert str(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS) not in str(body)


# ── Malformed input / exceptions cannot bypass the throttle ────────────────


def test_malformed_code_is_throttled_and_cannot_bypass_counter(client, mfa_user, tight_limits):
    ip = "10.10.7.1"
    statuses = []
    for garbage in ["", "abcdef", "12", "1" * 500]:
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        statuses.append(
            _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": garbage}).status_code
        )
    # 4 garbage attempts already meets MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS (3)
    # under tight_limits -- the last one must be throttled, not a 400 that
    # silently never counted.
    assert statuses[-1] == 429


def test_exception_during_verification_cannot_bypass_throttle(client, mfa_user, tight_limits, monkeypatch):
    """Simulates a broken/undecryptable device: crypto.decrypt raises for
    every candidate. The request must still fail safely (never 500) and
    still count as a throttled attempt -- not silently skip the counter.
    """
    def _broken_decrypt(_ciphertext):
        raise RuntimeError("simulated decrypt failure")

    monkeypatch.setattr(mfa_service.crypto, "decrypt", _broken_decrypt)

    ip = "10.10.8.1"
    statuses = []
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        code = "123456"
        statuses.append(_client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code}).status_code)

    assert 500 not in statuses
    assert statuses[-1] == 429


# ── Redis failure behavior ───────────────────────────────────────────────


def test_redis_unavailable_falls_back_and_still_throttles(client, mfa_user, tight_limits, monkeypatch):
    class _Broken:
        def __getattr__(self, name):
            raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(rate_limit, "_redis", _Broken())
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.9.1"

    responses = []
    for _ in range(settings.MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS + 2):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        responses.append(_client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}))

    # Not fail-open: still throttles once the (tighter) fallback
    # threshold is crossed.
    assert responses[-1].status_code == 429
    # Not fail-closed either: attempts within the fallback budget were
    # processed as normal 400s, not blocked outright.
    assert responses[0].status_code == 400


def test_redis_unavailable_does_not_block_a_correct_verification(client, mfa_user, tight_limits, monkeypatch):
    class _Broken:
        def __getattr__(self, name):
            raise ConnectionError("simulated redis outage")

    monkeypatch.setattr(rate_limit, "_redis", _Broken())
    token = _fresh_challenge_token(_client_at("10.10.10.1"), mfa_user)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    resp = _client_at("10.10.10.1").post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert resp.status_code == 200


def test_redis_fallback_in_process_state_is_bounded(client, tight_limits, monkeypatch):
    """The fallback dict is shared with login_throttle_service (same
    `_fallback` singleton, app/core/rate_limit.py) and capped at
    RATE_LIMIT_FALLBACK_MAX_KEYS -- exercised directly here rather than by
    generating tens of thousands of real HTTP requests."""
    monkeypatch.setattr(settings, "RATE_LIMIT_FALLBACK_MAX_KEYS", 5)
    for i in range(20):
        rate_limit._fallback.record_attempt(
            f"mfaratelimit:test:{i}", f"mfaratelimit:test:{i}:lock",
            settings.MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS, settings.MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS,
        )
    assert len(rate_limit._fallback._counters) + len(rate_limit._fallback._locks) <= 5


# ── Expiry / recovery ────────────────────────────────────────────────────


def test_expired_pair_window_starts_fresh_without_locking(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.11.1"
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS - 1):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        resp = _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})
        assert resp.status_code == 400

    time.sleep(settings.MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS + 0.5)
    token = _fresh_challenge_token(_client_at(ip), mfa_user)
    resp = _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})
    assert resp.status_code == 400


# ── Audit ────────────────────────────────────────────────────────────────


def test_rate_limit_trigger_emits_audit_event_with_expected_fields(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.12.1"
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    events = _events(event_type="mfa_rate_limit_triggered", actor_user_id=mfa_user["user_id"])
    pair_events = [e for e in events if e["metadata"].get("dimension") == "pair"]
    assert len(pair_events) == 1
    meta = pair_events[0]["metadata"]
    assert meta["ip"] == ip
    assert meta["lockout_seconds"] == settings.MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS


def test_audit_events_never_contain_secrets_codes_or_tokens(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.13.1"
    tokens_used = []
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        tokens_used.append(token)
        _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    events = _events(event_type="mfa_rate_limit_triggered", actor_user_id=mfa_user["user_id"])
    events += _events(event_type="mfa_verification_failed", actor_user_id=mfa_user["user_id"])
    for e in events:
        blob = str(e)
        assert mfa_user["secret"] not in blob
        assert wrong not in blob
        assert "encrypted_secret" not in blob
        for t in tokens_used:
            assert t not in blob


def test_no_duplicate_audit_events_while_lockout_still_active(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.14.1"
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 4):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong})

    events = _events(event_type="mfa_rate_limit_triggered", actor_user_id=mfa_user["user_id"])
    pair_events = [e for e in events if e["metadata"].get("dimension") == "pair"]
    assert len(pair_events) == 1


# ── Spoofed-header / client-controlled-identity resistance ─────────────────


def test_spoofed_organization_header_does_not_influence_throttle(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.15.1"
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        resp = _client_at(ip).post(
            "/users/me/mfa/challenge",
            json={"challenge_token": token, "code": wrong},
            headers={"X-Organization-Id": str(999999 + i)},
        )
    assert resp.status_code == 429  # still locked despite a different forged org id every request

    # The real user_id embedded in the challenge token is what's throttled
    # -- confirmed directly against the throttle keying (checked via
    # check_throttled/is_locked, not any dimension in particular -- with a
    # constant IP the pair dimension may trip before the account dimension
    # alone would, same as the generic "eventually throttles" test above).
    throttled = mfa_throttle_service.check_throttled(mfa_user["user_id"], ip)
    assert throttled.locked is True


def test_spoofed_user_id_header_cannot_reset_or_redirect_the_counter(client, mfa_user, configured_crypto, tight_limits):
    other = _register_and_login(client)
    other_headers = _auth_header(other["access_token"])
    other["secret"] = _enable_mfa(client, other_headers)
    other["user_id"] = _user_id(client, other["access_token"])

    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.16.1"
    for i in range(settings.MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS + 1):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        resp = _client_at(ip).post(
            "/users/me/mfa/challenge",
            json={"challenge_token": token, "code": wrong},
            headers={"X-User-Id": str(other["user_id"])},
        )
    assert resp.status_code == 429

    # mfa_user (the real, token-embedded identity) is throttled...
    real_throttled = mfa_throttle_service.check_throttled(mfa_user["user_id"], ip)
    assert real_throttled.locked is True
    # ...but `other` (only ever named in the forged header, never the
    # real challenge_token, and never itself sent a request on this IP)
    # is not.
    other_throttled = mfa_throttle_service.check_throttled(other["user_id"], "203.0.113.250")
    assert other_throttled.locked is False


# ── Concurrency / atomicity ─────────────────────────────────────────────────


def test_concurrent_attempts_cannot_bypass_atomic_counter(client, mfa_user, tight_limits):
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.17.1"
    tokens = [_fresh_challenge_token(_client_at(ip), mfa_user) for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5)]

    def _attempt(tok):
        return _client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": tok, "code": wrong})

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(_attempt, tokens))

    events = _events(event_type="mfa_rate_limit_triggered", actor_user_id=mfa_user["user_id"])
    pair_events = [e for e in events if e["metadata"].get("dimension") == "pair"]
    # Exactly one lockout transition recorded, however the concurrent
    # burst interleaved -- the underlying atomic Lua script
    # (app/core/rate_limit.py::_INCR_AND_LOCK_SCRIPT, already covered
    # directly by test_concurrent_failures_are_atomic_no_overshoot in
    # tests/test_login_rate_limiting.py) is what this test confirms
    # holds for this feature's own keys/dimension too.
    assert len(pair_events) == 1


# ── Config wiring sanity ────────────────────────────────────────────────────


def test_mfa_rate_limiting_disableable_via_settings(client, mfa_user, tight_limits, monkeypatch):
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ENABLED", False)
    wrong = _wrong_code(mfa_service._totp_code_at(mfa_user["secret"], int(time.time())))
    ip = "10.10.18.1"
    responses = []
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5):
        token = _fresh_challenge_token(_client_at(ip), mfa_user)
        responses.append(_client_at(ip).post("/users/me/mfa/challenge", json={"challenge_token": token, "code": wrong}))
    assert all(r.status_code == 400 for r in responses)


# ── Scope boundary: enrollment-verify is a different threat model ──────────


def test_totp_enrollment_verify_endpoint_not_covered_by_this_throttle(client, configured_crypto, tight_limits):
    """POST /users/me/mfa/totp/verify (self-enrollment confirmation) is
    gated by get_current_user -- unlike /users/me/mfa/challenge, a caller
    here already holds a real, valid access token, so brute-forcing their
    own new device's code grants no access they don't already have. This
    control deliberately does not extend to that endpoint (see
    docs/security-mfa-challenge-throttling.md) -- asserted here as a
    documented scope boundary, not a gap this test is meant to catch
    later."""
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()

    last = None
    for _ in range(settings.MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS + 5):
        last = client.post(
            "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": "000000"}, headers=headers
        )
    assert last.status_code == 400  # never 429 -- this endpoint isn't throttled by this PR
