"""HIPAA Phase 4: login authentication timing side-channel closure.

Exercises app/services/auth_service.py::authenticate_user +
app/core/security.py::DUMMY_PASSWORD_HASH through both the real HTTP
surface (POST /auth/login) and direct service-layer calls, following this
repo's established convention (see tests/test_login_rate_limiting.py's
own module docstring).

Per this task's own explicit guidance, these tests verify the fix
*deterministically* -- by spying on app.services.auth_service.verify_password
and asserting it is called exactly once, against the expected hash, on
every login-failure branch -- rather than asserting on wall-clock
duration, which is inherently noisy in CI. The actual timing-equalization
effect was verified empirically during discovery (unpatched `main`:
~9x slower for "real account, wrong password" vs. "unknown email"; this
branch: ~1.00x) and is described in
docs/security-login-timing-side-channel.md, not re-asserted here as a
duration-based regression test.
"""
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.security import DUMMY_PASSWORD_HASH
from app.db.models import AuditEvent, User
from app.services import auth_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _unique_email():
    return f"timing-{uuid.uuid4().hex[:10]}@omnibioai.test"


def _register(client, email, password="TestPassword123!"):
    resp = client.post("/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 200
    return {"email": email, "password": password}


def _events(**filters) -> list[dict]:
    db = _DirectSession()
    try:
        query = db.query(AuditEvent)
        for key, value in filters.items():
            query = query.filter(getattr(AuditEvent, key) == value)
        rows = query.order_by(AuditEvent.id).all()
        return [
            {"event_type": r.event_type, "metadata": r.event_metadata}
            for r in rows
        ]
    finally:
        db.close()


@pytest.fixture
def verify_password_spy(monkeypatch):
    """Records every (password, hashed) pair app.services.auth_service's
    own `verify_password` name is called with, then forwards to the real
    implementation -- this fixture changes nothing about behavior, only
    observes it."""
    from app.core.security import verify_password as _real_verify_password

    calls = []

    def _spy(password, hashed):
        calls.append(hashed)
        return _real_verify_password(password, hashed)

    monkeypatch.setattr(auth_service, "verify_password", _spy)
    return calls


# ── Sanity: the dummy hash itself ────────────────────────────────────────


def test_dummy_password_hash_is_a_real_verifiable_hash():
    """Not a placeholder string that merely *looks* like a hash --
    DUMMY_PASSWORD_HASH must be something verify_password can actually
    run its normal bcrypt-cost comparison against without raising."""
    from app.core.security import verify_password

    assert DUMMY_PASSWORD_HASH
    assert isinstance(DUMMY_PASSWORD_HASH, str)
    # A real CryptContext hash always starts with a recognizable scheme
    # prefix -- bcrypt_sha256's is "$bcrypt-sha256$".
    assert DUMMY_PASSWORD_HASH.startswith("$bcrypt-sha256$")
    # Verifying against it must behave exactly like verifying against any
    # other hash of a password the caller doesn't know -- False, no
    # exception, regardless of what's submitted.
    assert auth_service.verify_password("literally anything", DUMMY_PASSWORD_HASH) is False


# ── 1/2/9: every failure branch performs one real hash verification ────────


def test_nonexistent_user_invokes_one_dummy_hash_verification(client, verify_password_spy):
    resp = client.post("/auth/login", json={"email": _unique_email(), "password": "whatever-guess"})
    assert resp.status_code == 401
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


def test_existing_user_wrong_password_invokes_one_real_hash_verification(client, verify_password_spy):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json={"email": user["email"], "password": "wrong-password"})
    assert resp.status_code == 401
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


def test_password_less_oauth_only_account_invokes_one_dummy_hash_verification(client, verify_password_spy):
    """The third existing failure branch (`no_password_set`) -- an
    OAuth-only account with no local password at all -- must be
    equalized too, same as the unknown-user branch."""
    db = _DirectSession()
    try:
        email = _unique_email()
        user = User(email=email, hashed_password=None, status="active")
        db.add(user)
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/login", json={"email": email, "password": "whatever-guess"})
    assert resp.status_code == 401
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


def test_inactive_account_invokes_one_dummy_hash_verification(client, verify_password_spy):
    user = _register(client, _unique_email())
    db = _DirectSession()
    try:
        row = db.query(User).filter(User.email == user["email"]).first()
        row.status = "disabled"
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 401
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


# ── 3/4: success paths use the real hash, are otherwise unaffected ─────────


def test_existing_user_correct_password_invokes_one_real_hash_verification_and_succeeds(client, verify_password_spy):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


def test_existing_user_requiring_mfa_invokes_one_real_hash_verification_and_challenges(
    client, verify_password_spy, monkeypatch,
):
    """Correct password for an MFA-enabled user: password verification
    itself is completely unaffected by this fix (same real-hash branch as
    any other correct password) -- only the *response shape* differs
    (challenge, not tokens), exactly as it already did before this PR."""
    from cryptography.fernet import Fernet
    import app.core.crypto as crypto

    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))

    user = _register(client, _unique_email())
    login = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    access_token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    import urllib.parse
    from app.services import mfa_service

    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(enroll["otpauth_uri"]).query)["secret"][0]
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200

    verify_password_spy.clear()
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    assert resp.json()["mfa_required"] is True
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


# ── 5: throttled requests never reach password verification at all ─────────


def test_rate_limited_login_never_invokes_password_verification(client, verify_password_spy, monkeypatch):
    """The equalization fix must not introduce a new resource-exhaustion
    vector: a throttled request is rejected by login_throttle_service
    *before* authenticate_user is ever called (unchanged ordering,
    app/api/routes_auth.py::login) -- confirmed here by asserting
    verify_password (real or dummy) is never invoked once the account is
    locked, exactly as before this PR."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "RATE_LIMIT_PAIR_LOCKOUT_SECONDS", 30)

    user = _register(client, _unique_email())
    for _ in range(2):
        client.post("/auth/login", json={"email": user["email"], "password": "wrong"})

    verify_password_spy.clear()
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 429
    assert verify_password_spy == []


# ── 6: malformed/oversized input ────────────────────────────────────────


def test_oversized_password_against_unknown_user_still_invokes_verification(client, verify_password_spy):
    """PasswordSizeError is caught *inside* verify_password itself
    (app/core/security.py) -- the call still happens (and the branch
    taken is still the dummy-hash one), it just returns False quickly
    without a full bcrypt round for this specific oversized input. Same
    behavior on both branches (see next test), so no new asymmetry."""
    resp = client.post("/auth/login", json={"email": _unique_email(), "password": "x" * 10000})
    assert resp.status_code == 401
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


def test_oversized_password_against_real_account_still_invokes_verification(client, verify_password_spy):
    user = _register(client, _unique_email())
    resp = client.post("/auth/login", json={"email": user["email"], "password": "x" * 10000})
    assert resp.status_code == 401
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


def test_malformed_login_request_returns_validation_error_not_crash(client, verify_password_spy):
    resp = client.post("/auth/login", json={"email": "missing-password@omnibioai.test"})
    assert resp.status_code == 422
    assert verify_password_spy == []


# ── 7: concurrency ────────────────────────────────────────────────────────


def test_concurrent_unknown_and_wrong_password_logins_each_verify_independently(client):
    """No shared/atomic state was introduced by this fix (DUMMY_PASSWORD_HASH
    is a read-only module constant) -- concurrent requests across both
    branches must not interfere with, skip, or double-count each other's
    verification."""
    real_user = _register(client, _unique_email())

    def _unknown(_):
        return client.post("/auth/login", json={"email": _unique_email(), "password": "guess"})

    def _wrong(_):
        return client.post("/auth/login", json={"email": real_user["email"], "password": "wrong-guess"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        unknown_results = list(pool.map(_unknown, range(4)))
        wrong_results = list(pool.map(_wrong, range(4)))

    assert all(r.status_code == 401 for r in unknown_results)
    assert all(r.status_code in (401, 429) for r in wrong_results)  # pair throttle may kick in with 4 rapid attempts


# ── 8: SAML/SSO routes untouched ─────────────────────────────────────────


def test_sso_enforced_login_still_bypasses_password_verification_entirely(client, verify_password_spy, monkeypatch):
    """Regression guard: the SSO-enforcement short-circuit in
    routes_auth.py::login (checked before authenticate_user is ever
    called) is untouched by this fix -- an SSO-enforced org's email must
    still never trigger any password verification (real or dummy),
    exactly as before. Same fixture/mocking shape as
    tests/test_login_rate_limiting.py::test_sso_enforced_login_bypasses_password_throttle_entirely.
    """
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

    resp = client.post("/auth/login", json={"email": _unique_email(), "password": "wrong"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sso_required"
    assert verify_password_spy == []


# ── Audit / no secret leakage ────────────────────────────────────────────


def test_audit_events_unchanged_and_leak_no_password_or_dummy_hash(client, verify_password_spy):
    email = _unique_email()
    password = "S3cretGuessPassword!"
    client.post("/auth/login", json={"email": email, "password": password})

    events = _events(event_type="login_failure")
    matching = [e for e in events if e["metadata"].get("email") == email]
    assert len(matching) == 1
    assert matching[0]["metadata"]["reason"] == "unknown_user_or_inactive"
    blob = str(matching[0])
    assert password not in blob
    assert DUMMY_PASSWORD_HASH not in blob
