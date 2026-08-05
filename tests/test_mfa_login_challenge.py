"""PR11.5.3 (Enterprise MFA Login Challenge). Follows this repo's
established convention: real HTTP calls through real routes/services
against the shared sqlite test DB, rows/audit events read back via a
second, direct session -- never mocks of auth_service/mfa_service
themselves (provider-boundary functions like exchange_code_for_userinfo
are mocked, same level tests/test_oauth.py's own `_mock_exchange`
already mocks at -- not the MFA logic under test). Each test file is
self-contained (local helpers), matching this repo's per-file
duplication convention.
"""
import time
import urllib.parse
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import _sign, create_oauth_state_token, create_sso_state_token, decode_token
from app.core.oauth_providers import PROVIDERS
from app.db.models import AuditEvent, OAuthAccount, Organization, OrganizationSSOConfig, RefreshToken, User
from app.services import mfa_service, oauth_service, org_oidc_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_SSO_ISSUER = "https://idp.mfa-challenge-test.example.com"
_SSO_CLIENT_ID = "mfa-test-client-id"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"mfa-challenge-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _user_row(user_id: int) -> User:
    db = _DirectSession()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


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
                "resource_type": r.resource_type, "resource_id": r.resource_id,
                "before_state": r.before_state, "after_state": r.after_state,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _assert_no_secret_leakage(event: dict, *, secret: str | None = None, code: str | None = None) -> None:
    blob = str(event["before_state"]) + str(event["after_state"]) + str(event["metadata"])
    for forbidden in ("encrypted_secret", "otpauth://", "challenge_token"):
        assert forbidden not in blob, f"{forbidden!r} leaked into audit event: {event}"
    if secret:
        assert secret not in blob, f"plaintext TOTP secret leaked into audit event: {event}"
    if code:
        assert code not in blob, f"OTP code leaked into audit event: {event}"


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_config.py's/tests/test_mfa.py's
    fixture of the same name."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _enable_mfa(client, headers) -> str:
    """Enrolls + verifies a TOTP device for the caller, returning the
    plaintext secret so tests can compute future codes. Requires
    configured_crypto to be in effect."""
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


@pytest.fixture
def mfa_user(client, configured_crypto):
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    user["secret"] = _enable_mfa(client, headers)
    return user


def _expired_challenge_token(user_id: int) -> str:
    from datetime import datetime, timedelta

    return _sign({
        "type": "mfa_challenge",
        "user_id": user_id,
        "mfa_required": True,
        "auth_method": "password",
        "idp_org_id": None,
        "exp": datetime.utcnow() - timedelta(minutes=1),
        "jti": str(uuid.uuid4()),
    })


# ── Existing (non-MFA) users: response shape unchanged ──────────────────────


def test_login_without_mfa_returns_normal_tokens_unchanged(client):
    user = _register_and_login(client)
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "mfa_required" not in data  # strictly unchanged, not just additive


def test_access_token_carries_mfa_verified_claim_for_non_mfa_user(client):
    user = _register_and_login(client)
    payload = decode_token(user["access_token"])
    assert payload["mfa_verified"] is True


# ── MFA-enabled users: password login ────────────────────────────────────────


def test_login_with_mfa_enabled_returns_challenge_not_tokens(client, mfa_user):
    resp = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})

    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "mfa_required": True,
        "challenge_token": data["challenge_token"],
        "methods": ["totp"],
    }
    assert "access_token" not in data
    assert "refresh_token" not in data


def test_challenge_with_valid_code_returns_tokens(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code})

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

    payload = decode_token(data["access_token"])
    assert payload["mfa_verified"] is True
    assert payload["auth_method"] == "password"

    row = _user_row(_user_id(client, data["access_token"]))
    assert row.mfa_last_verified_at is not None


def test_challenge_with_invalid_code_rejected(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    correct = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    wrong = ("1" if correct[0] != "1" else "2") + correct[1:]

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": wrong})

    assert resp.status_code == 400


def test_expired_challenge_token_rejected(client, mfa_user):
    user_id = _user_id(client, mfa_user["access_token"])
    expired = _expired_challenge_token(user_id)
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": expired, "code": code})

    assert resp.status_code == 401


def test_challenge_token_cannot_be_reused(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))

    first = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code})
    assert first.status_code == 200

    second = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code})
    assert second.status_code == 401


def test_challenge_token_cannot_access_apis(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]

    resp = client.get("/users/me/mfa/devices", headers=_auth_header(challenge_token))

    assert resp.status_code == 401


def test_challenge_token_cannot_refresh_session(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]

    resp = client.post("/auth/refresh", json={"refresh_token": challenge_token})

    assert resp.status_code == 401
    # Never written to refresh_tokens -- confirms the rejection is because
    # no row exists, not an incidental side effect of some other check.
    db = _DirectSession()
    try:
        assert db.query(RefreshToken).filter(RefreshToken.token == challenge_token).first() is None
    finally:
        db.close()


def test_challenge_rejects_another_users_code(client, mfa_user):
    """Cross-user isolation: A's challenge_token can only ever be
    completed with A's own code -- B's correct code (for B's own device)
    must fail against A's challenge, since verification is scoped
    entirely to the user_id embedded in the token itself."""
    other = _register_and_login(client)
    other_headers = _auth_header(other["access_token"])
    other_secret = _enable_mfa(client, other_headers)

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    others_code = mfa_service._totp_code_at(other_secret, int(time.time()))

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": others_code})

    assert resp.status_code == 400  # token is fine, code just doesn't match this user's device


def test_stale_challenge_rejected_after_mfa_disabled(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]

    devices = client.get("/users/me/mfa/devices", headers=headers).json()
    for d in devices:
        client.delete(f"/users/me/mfa/devices/{d['id']}", headers=headers)

    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code})

    assert resp.status_code == 401


def test_refresh_works_normally_after_completing_mfa_challenge(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    tokens = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code}).json()

    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert resp.status_code == 200
    assert "access_token" in resp.json()


# ── Provider coverage: OAuth, SSO, license ───────────────────────────────────


@pytest.fixture
def configured_google(monkeypatch):
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


def test_oauth_login_with_mfa_enabled_returns_challenge(client, mfa_user, configured_google, monkeypatch):
    user_id = _user_id(client, mfa_user["access_token"])
    db = _DirectSession()
    try:
        db.add(OAuthAccount(user_id=user_id, provider="google", provider_user_id="google-mfa-uid", email=mfa_user["email"]))
        db.commit()
    finally:
        db.close()

    async def fake_exchange(provider, code, code_verifier=None):
        return "google-mfa-uid", mfa_user["email"]
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)

    state = create_oauth_state_token("google")
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "mfa_required"
    assert data["mfa_required"] is True
    assert "challenge_token" in data
    assert data["methods"] == ["totp"]
    assert "access_token" not in data


def test_sso_login_with_mfa_enabled_returns_challenge(client, mfa_user, monkeypatch):
    user_id = _user_id(client, mfa_user["access_token"])
    db = _DirectSession()
    try:
        org = Organization(slug=f"sso-mfa-org-{uuid.uuid4().hex[:8]}", name="SSO MFA Test Org")
        db.add(org)
        db.commit()
        db.refresh(org)

        config = OrganizationSSOConfig(
            organization_id=org.id,
            provider_type="oidc",
            issuer=_SSO_ISSUER,
            client_id=_SSO_CLIENT_ID,
            client_secret_encrypted="not-read-by-this-test",
            status="active",
        )
        db.add(config)
        db.commit()
        db.refresh(config)

        db.add(OAuthAccount(
            user_id=user_id, provider="oidc", provider_user_id="sso-mfa-sub",
            email=mfa_user["email"], organization_sso_config_id=config.id,
        ))
        db.commit()

        org_id, config_id, org_slug = org.id, config.id, org.slug
    finally:
        db.close()

    async def fake_claims(*args, **kwargs):
        return {"sub": "sso-mfa-sub", "email": mfa_user["email"]}
    monkeypatch.setattr(org_oidc_service, "exchange_code_for_id_token_claims", fake_claims)

    state = create_sso_state_token(org_id, config_id, "verifier", "nonce")
    resp = client.post(f"/auth/sso/{org_slug}/callback", json={"code": "fake-code", "state": state})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "mfa_required"
    assert data["mfa_required"] is True
    assert "challenge_token" in data
    assert data["methods"] == ["totp"]
    assert "access_token" not in data


def test_license_login_with_mfa_enabled_returns_challenge(client, mfa_user):
    from app.services import license_service

    db = _DirectSession()
    try:
        license_key = license_service.create_license(
            db, email=mfa_user["email"], plan="beta", platform="web", expires_days=None, max_uses=5
        )
        key = license_key.key
    finally:
        db.close()

    resp = client.post("/license/validate", json={"key": key, "email": mfa_user["email"], "platform": "web"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["mfa_required"] is True
    assert data["challenge_token"] is not None
    assert data["methods"] == ["totp"]
    assert data["access_token"] is None
    assert data["refresh_token"] is None


def test_license_login_without_mfa_unchanged(client):
    from app.services import license_service

    user = _register_and_login(client)
    db = _DirectSession()
    try:
        license_key = license_service.create_license(
            db, email=user["email"], plan="beta", platform="web", expires_days=None, max_uses=5
        )
        key = license_key.key
    finally:
        db.close()

    resp = client.post("/license/validate", json={"key": key, "email": user["email"], "platform": "web"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["mfa_required"] is False
    assert data["challenge_token"] is None
    assert data["access_token"] is not None


# ── Audit trail ──────────────────────────────────────────────────────────────


def test_mfa_challenge_required_audit_event_emitted_without_secrets(client, mfa_user):
    resp = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = resp.json()["challenge_token"]
    user_id = _user_id(client, mfa_user["access_token"])

    events = _events(event_type="mfa_challenge_required", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["metadata"]["authentication_method"] == "password"
    _assert_no_secret_leakage(events[0], secret=mfa_user["secret"])
    assert challenge_token not in str(events[0])


def test_mfa_verified_audit_event_emitted_without_secrets(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": code})
    user_id = _user_id(client, mfa_user["access_token"])

    events = _events(event_type="mfa_verified", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["metadata"]["authentication_method"] == "password"
    _assert_no_secret_leakage(events[0], secret=mfa_user["secret"], code=code)


def test_mfa_verification_failed_audit_event_emitted_on_wrong_code(client, mfa_user):
    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    correct = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    wrong = ("1" if correct[0] != "1" else "2") + correct[1:]
    client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": wrong})
    user_id = _user_id(client, mfa_user["access_token"])

    events = _events(event_type="mfa_verification_failed", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["metadata"]["authentication_method"] == "password"
    _assert_no_secret_leakage(events[0], secret=mfa_user["secret"], code=wrong)
