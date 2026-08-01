"""Phase 2 PR2: PKCE (RFC 7636) added to the existing 3-provider OAuth
flow. Hardening only -- test_oauth.py's full existing suite (unmodified in
behavior, only its mock's signature was extended) proves this didn't
change the client-visible login contract; these tests prove the PKCE
mechanics themselves.
"""

import asyncio
import base64
import hashlib
import uuid
from urllib.parse import parse_qs, urlparse

import pytest

from app.core.jwt import create_oauth_state_token, decode_token
from app.core.oauth_providers import PROVIDERS
from app.services import oauth_service


@pytest.fixture
def configured_google(monkeypatch):
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


# ── State token carries code_verifier ────────────────────────────────────────


def test_state_token_embeds_code_verifier():
    state = create_oauth_state_token("google", code_verifier="abc123verifier")
    payload = decode_token(state)
    assert payload["code_verifier"] == "abc123verifier"


def test_state_token_without_code_verifier_omits_the_field():
    """A state token minted without PKCE must not carry a bogus/empty
    code_verifier claim -- exchange_code_for_userinfo treats its absence
    as "don't send one," not as an empty string, which matters for the
    brief pre-deploy/post-deploy window where both kinds can exist."""
    state = create_oauth_state_token("google")
    payload = decode_token(state)
    assert "code_verifier" not in payload


# ── Authorize URL carries the matching code_challenge ───────────────────────


def test_build_authorize_url_includes_pkce_params(configured_google):
    url = oauth_service.build_authorize_url("google")
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url


def test_authorize_url_challenge_matches_state_token_verifier(configured_google):
    """The code_challenge sent to the provider must be the S256 hash of
    the exact code_verifier embedded in this same call's state token -- if
    these ever drift apart, PKCE silently stops verifying anything."""
    url = oauth_service.build_authorize_url("google")
    query = parse_qs(urlparse(url).query)

    state_payload = decode_token(query["state"][0])
    code_verifier = state_payload["code_verifier"]
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )

    assert query["code_challenge"][0] == expected_challenge


def test_login_route_redirect_contains_pkce_params(client, configured_google):
    resp = client.get("/auth/google/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert "code_challenge=" in location
    assert "code_challenge_method=S256" in location


def test_each_authorize_call_generates_a_distinct_verifier(configured_google):
    """A reused/predictable code_verifier would defeat the point of PKCE --
    every authorize call must mint its own."""
    url1 = oauth_service.build_authorize_url("google")
    url2 = oauth_service.build_authorize_url("google")
    v1 = decode_token(parse_qs(urlparse(url1).query)["state"][0])["code_verifier"]
    v2 = decode_token(parse_qs(urlparse(url2).query)["state"][0])["code_verifier"]
    assert v1 != v2


# ── code_verifier reaches the token exchange request ────────────────────────


class _FakeResponse:
    def __init__(self, status_code, json_body):
        self.status_code = status_code
        self._json_body = json_body
        self.text = str(json_body)

    def json(self):
        return self._json_body


class _FakeAsyncClient:
    """Captures the outgoing POST body to the provider's token endpoint and
    returns a canned successful token+userinfo response -- drives
    exchange_code_for_userinfo end-to-end without a real network call."""

    captured_post_data = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, headers=None):
        _FakeAsyncClient.captured_post_data = data
        return _FakeResponse(200, {"access_token": "fake-provider-token"})

    async def get(self, url, headers=None):
        return _FakeResponse(200, {"sub": f"pkce-uid-{uuid.uuid4().hex[:8]}", "email": f"pkce-{uuid.uuid4().hex[:8]}@omnibioai.test"})


@pytest.fixture(autouse=True)
def _reset_fake_client_capture():
    _FakeAsyncClient.captured_post_data = None
    yield


def test_exchange_sends_code_verifier_when_present(monkeypatch, configured_google):
    monkeypatch.setattr(oauth_service.httpx, "AsyncClient", _FakeAsyncClient)

    asyncio.run(
        oauth_service.exchange_code_for_userinfo("google", "fake-code", code_verifier="the-real-verifier")
    )

    assert _FakeAsyncClient.captured_post_data["code_verifier"] == "the-real-verifier"


def test_exchange_omits_code_verifier_when_absent(monkeypatch, configured_google):
    monkeypatch.setattr(oauth_service.httpx, "AsyncClient", _FakeAsyncClient)

    asyncio.run(oauth_service.exchange_code_for_userinfo("google", "fake-code"))

    assert "code_verifier" not in _FakeAsyncClient.captured_post_data


# ── Full round trip through the real routes ─────────────────────────────────


def test_full_login_flow_with_real_pkce_state_still_succeeds(client, configured_google, monkeypatch):
    """End-to-end through the actual routes: build_authorize_url mints the
    real PKCE state, /auth/google/callback decodes it and forwards
    code_verifier through to the token exchange -- proves the whole chain
    works, not just the unit pieces above."""
    monkeypatch.setattr(oauth_service.httpx, "AsyncClient", _FakeAsyncClient)

    login_resp = client.get("/auth/google/login", follow_redirects=False)
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]

    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    expected_verifier = decode_token(state)["code_verifier"]
    assert _FakeAsyncClient.captured_post_data["code_verifier"] == expected_verifier


def test_callback_with_state_missing_code_verifier_still_succeeds(client, configured_google, monkeypatch):
    """Backward compatibility for the brief rolling-deploy window: a state
    token minted without PKCE (simulated here directly) must still
    complete login, just without sending code_verifier."""
    monkeypatch.setattr(oauth_service.httpx, "AsyncClient", _FakeAsyncClient)

    state = create_oauth_state_token("google")  # no code_verifier
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert "code_verifier" not in _FakeAsyncClient.captured_post_data
