import uuid

import pytest

from app.core.jwt import create_oauth_state_token
from app.core.oauth_providers import PROVIDERS
from app.services import oauth_service


@pytest.fixture
def configured_google(monkeypatch):
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


def _mock_exchange(monkeypatch, provider_user_id, email):
    async def fake_exchange(provider, code):
        return provider_user_id, email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)


# ── Basic provider validation ───────────────────────────────────────────────────

def test_unknown_provider_returns_404(client):
    resp = client.get("/auth/bitbucket/login")
    assert resp.status_code == 404


def test_unconfigured_provider_returns_503(client, monkeypatch):
    # Real credentials are loaded from .env in this environment, so force
    # microsoft's config empty for this test to exercise the "not configured" path.
    monkeypatch.setitem(PROVIDERS["microsoft"], "client_id", "")
    monkeypatch.setitem(PROVIDERS["microsoft"], "client_secret", "")
    resp = client.get("/auth/microsoft/login")
    assert resp.status_code == 503


# ── Login redirect ───────────────────────────────────────────────────────────────

def test_login_redirects_to_provider_with_state(client, configured_google):
    resp = client.get("/auth/google/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert "accounts.google.com" in location
    assert "client_id=test-google-client-id" in location
    assert "state=" in location


# ── Callback: new account ───────────────────────────────────────────────────────

def test_callback_creates_new_user_and_issues_token(client, configured_google, monkeypatch):
    email = f"oauth-{uuid.uuid4().hex[:8]}@omnibioai.test"
    _mock_exchange(monkeypatch, "google-uid-1", email)
    state = create_oauth_state_token("google")

    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "access_token" in data
    assert "refresh_token" in data

    validate = client.post("/auth/validate", json={"token": data["access_token"]})
    assert validate.json()["valid"] is True
    assert validate.json()["email"] == email


def test_callback_invalid_state_returns_400(client, configured_google, monkeypatch):
    _mock_exchange(monkeypatch, "google-uid-2", "whoever@omnibioai.test")
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": "not-a-real-token"})
    assert resp.status_code == 400


def test_callback_state_for_wrong_provider_rejected(client, configured_google, monkeypatch):
    _mock_exchange(monkeypatch, "google-uid-3", "whoever2@omnibioai.test")
    github_state = create_oauth_state_token("github")  # minted for a different provider
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": github_state})
    assert resp.status_code == 400


def test_same_oauth_identity_logs_in_on_repeat(client, configured_google, monkeypatch):
    email = f"oauth-repeat-{uuid.uuid4().hex[:8]}@omnibioai.test"
    _mock_exchange(monkeypatch, "google-uid-repeat", email)
    state1 = create_oauth_state_token("google")
    first = client.post("/auth/google/callback", json={"code": "c1", "state": state1})
    assert first.json()["status"] == "ok"

    state2 = create_oauth_state_token("google")
    second = client.post("/auth/google/callback", json={"code": "c2", "state": state2})
    assert second.json()["status"] == "ok"

    v1 = client.post("/auth/validate", json={"token": first.json()["access_token"]})
    v2 = client.post("/auth/validate", json={"token": second.json()["access_token"]})
    assert v1.json()["user_id"] == v2.json()["user_id"]


# ── GET callback redirects the browser back, even on failure ────────────────────

def test_get_callback_success_redirects_with_token(client, configured_google, monkeypatch):
    email = f"oauth-redirect-{uuid.uuid4().hex[:8]}@omnibioai.test"
    _mock_exchange(monkeypatch, "google-uid-redirect", email)
    state = create_oauth_state_token("google")

    resp = client.get(
        f"/auth/google/callback?code=fake-code&state={state}", follow_redirects=False
    )
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert "/oauth-complete?" in location
    assert "access_token=" in location
    assert "status=ok" in location


def test_get_callback_failure_redirects_with_error_not_raw_json(client, configured_google):
    # invalid state — must still redirect, not surface a bare 400 JSON page
    resp = client.get(
        "/auth/google/callback?code=fake-code&state=not-a-real-token", follow_redirects=False
    )
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert "/oauth-complete?" in location
    assert "status=error" in location


# ── Callback: existing email → link confirmation required ───────────────────────

def test_callback_existing_email_requires_link_confirmation(client, configured_google, monkeypatch, registered_user):
    _mock_exchange(monkeypatch, "google-uid-link", registered_user["email"])
    state = create_oauth_state_token("google")

    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert data["email"] == registered_user["email"]
    assert "link_token" in data


def test_link_confirm_wrong_password_returns_401(client, configured_google, monkeypatch, registered_user):
    _mock_exchange(monkeypatch, "google-uid-link-wrong-pw", registered_user["email"])
    state = create_oauth_state_token("google")
    link_resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    link_token = link_resp.json()["link_token"]

    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})
    assert resp.status_code == 401


def test_link_confirm_success_links_account_and_issues_token(client, configured_google, monkeypatch, registered_user):
    _mock_exchange(monkeypatch, "google-uid-link-ok", registered_user["email"])
    state = create_oauth_state_token("google")
    link_resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    link_token = link_resp.json()["link_token"]

    resp = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": registered_user["password"]}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data

    # subsequent logins via the same provider identity go straight through
    state2 = create_oauth_state_token("google")
    second = client.post("/auth/google/callback", json={"code": "fake-code-2", "state": state2})
    assert second.json()["status"] == "ok"


def test_link_confirm_invalid_token_returns_400(client):
    resp = client.post("/auth/link/confirm", json={"link_token": "garbage", "password": "whatever"})
    assert resp.status_code == 400


# ── OAuth-only accounts can't password-login ─────────────────────────────────────

def test_oauth_only_account_cannot_password_login(client, configured_google, monkeypatch):
    email = f"oauth-nopass-{uuid.uuid4().hex[:8]}@omnibioai.test"
    _mock_exchange(monkeypatch, "google-uid-nopass", email)
    state = create_oauth_state_token("google")
    client.post("/auth/google/callback", json={"code": "fake-code", "state": state})

    resp = client.post("/auth/login", json={"email": email, "password": "anything"})
    assert resp.status_code == 401


# ── Existing email/password login is unaffected ──────────────────────────────────

def test_existing_password_login_still_works(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    assert "access_token" in resp.json()
