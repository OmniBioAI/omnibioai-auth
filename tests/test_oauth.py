"""Consumer OAuth login (Google, with the provider code exchange mocked): provider
lookup errors, the redirect carrying state, callback state validation, new-user
creation and repeat logins, redirect behaviour of the GET callback, link
confirmation for an existing email, and OAuth-only accounts having no password
login.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_oauth_state_token
from app.core.oauth_providers import PROVIDERS
from app.db.models import User
from app.services import oauth_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def configured_google(monkeypatch):
    """Configure the Google OAuth provider with test client credentials for the duration of the
    test.
    """
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


def _mock_exchange(monkeypatch, provider_user_id, email):
    """Replace the provider code exchange with a stub that returns the given provider user id and
    email and ignores any PKCE verifier.
    """
    # code_verifier accepted (Phase 2 PR2's PKCE plumbing) but ignored --
    # these tests exercise the account-linking logic downstream of the
    # exchange, not the exchange/PKCE mechanics themselves (see
    # tests/test_pkce.py for that).
    async def fake_exchange(provider, code, code_verifier=None):
        return provider_user_id, email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)


# ── Basic provider validation ───────────────────────────────────────────────────

def test_unknown_provider_returns_404(client):
    """Starting login for an unknown provider returns 404."""
    resp = client.get("/auth/bitbucket/login")
    assert resp.status_code == 404


def test_unconfigured_provider_returns_503(client, monkeypatch):
    """Starting login for a provider without configured credentials returns 503."""
    # Real credentials are loaded from .env in this environment, so force
    # microsoft's config empty for this test to exercise the "not configured" path.
    monkeypatch.setitem(PROVIDERS["microsoft"], "client_id", "")
    monkeypatch.setitem(PROVIDERS["microsoft"], "client_secret", "")
    resp = client.get("/auth/microsoft/login")
    assert resp.status_code == 503


# ── Login redirect ───────────────────────────────────────────────────────────────

def test_login_redirects_to_provider_with_state(client, configured_google):
    """Provider login redirects to the provider's authorize URL carrying the configured client_id
    and a state parameter.
    """
    resp = client.get("/auth/google/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert "accounts.google.com" in location
    assert "client_id=test-google-client-id" in location
    assert "state=" in location


# ── Callback: new account ───────────────────────────────────────────────────────

def test_callback_creates_new_user_and_issues_token(client, configured_google, monkeypatch):
    """The callback for a new provider identity creates a user and returns status "ok" with tokens
    that validate for that email, recording authentication_method "oauth" and a last-login time.
    """
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

    # PR11.1: persisted users.authentication_method for the 3-provider
    # consumer-OAuth flow (google/github/microsoft) is "oauth" -- distinct
    # from enterprise SSO's "oidc" (see test_sso_login.py).
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user.authentication_method == "oauth"
        assert user.last_login_at is not None
    finally:
        db.close()


def test_callback_invalid_state_returns_400(client, configured_google, monkeypatch):
    """A callback with an invalid state token returns 400."""
    _mock_exchange(monkeypatch, "google-uid-2", "whoever@omnibioai.test")
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": "not-a-real-token"})
    assert resp.status_code == 400


def test_callback_state_for_wrong_provider_rejected(client, configured_google, monkeypatch):
    """A state token minted for a different provider is rejected with 400."""
    _mock_exchange(monkeypatch, "google-uid-3", "whoever2@omnibioai.test")
    github_state = create_oauth_state_token("github")  # minted for a different provider
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": github_state})
    assert resp.status_code == 400


def test_same_oauth_identity_logs_in_on_repeat(client, configured_google, monkeypatch):
    """The same provider identity logs in to the same user on repeated callbacks."""
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
    """A successful GET callback redirects to /oauth-complete with status=ok and an access_token."""
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
    """A GET callback with an invalid state redirects to /oauth-complete with status=error instead
    of returning raw JSON.
    """
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
    """A provider identity whose email belongs to an existing account returns status "link_required"
    with a link token instead of logging in.
    """
    _mock_exchange(monkeypatch, "google-uid-link", registered_user["email"])
    state = create_oauth_state_token("google")

    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert data["email"] == registered_user["email"]
    assert "link_token" in data


def test_link_confirm_wrong_password_returns_401(client, configured_google, monkeypatch, registered_user):
    """Confirming an account link with the wrong password returns 401."""
    _mock_exchange(monkeypatch, "google-uid-link-wrong-pw", registered_user["email"])
    state = create_oauth_state_token("google")
    link_resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    link_token = link_resp.json()["link_token"]

    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})
    assert resp.status_code == 401


def test_link_confirm_success_links_account_and_issues_token(client, configured_google, monkeypatch, registered_user):
    """Confirming the link with the correct password returns tokens and links the identity, so a
    later provider callback logs in directly.
    """
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
    """Confirming a link with an invalid link token returns 400."""
    resp = client.post("/auth/link/confirm", json={"link_token": "garbage", "password": "whatever"})
    assert resp.status_code == 400


# ── OAuth-only accounts can't password-login ─────────────────────────────────────

def test_oauth_only_account_cannot_password_login(client, configured_google, monkeypatch):
    """An account created through OAuth has no password, so a password login attempt returns 401."""
    email = f"oauth-nopass-{uuid.uuid4().hex[:8]}@omnibioai.test"
    _mock_exchange(monkeypatch, "google-uid-nopass", email)
    state = create_oauth_state_token("google")
    client.post("/auth/google/callback", json={"code": "fake-code", "state": state})

    resp = client.post("/auth/login", json={"email": email, "password": "anything"})
    assert resp.status_code == 401


# ── Existing email/password login is unaffected ──────────────────────────────────

def test_existing_password_login_still_works(client, registered_user):
    """Password login for a registered user still returns 200 with an access token."""
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    assert "access_token" in resp.json()
