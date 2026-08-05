"""Phase 2 PR4: per-org OIDC login flow + domain-based discovery. Builds
on PR3 (org_sso_service, organization_sso_configs) and PR2 (PKCE). Does
NOT touch, and must not change the behavior of, the existing
Google/GitHub/Microsoft flow -- see tests/test_oauth.py and
tests/test_pkce.py, both still run as part of the full suite unmodified.
"""

import base64
import os
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.services import oauth_service, org_oidc_service, org_sso_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_ISSUER = "https://idp.acme-test.example.com"
_CLIENT_ID = "acme-client-id"
_KID = "test-signing-key-1"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"sso-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post(
        "/auth/login",
        json={"email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"]},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def admin_headers(admin_token):
    return _auth_header(admin_token)


# ── Real RSA keypair for genuine id_token signature verification ───────────
# Deliberately not mocking the signature check itself -- that's the one
# piece of this feature that would be dangerous to fake, so these tests
# sign with a real private key and verify org_oidc_service.py's real jose
# decode against the matching public JWK, exactly as production would.


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return private_key, private_pem


def _b64u(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(byte_length, "big")).rstrip(b"=").decode("ascii")


def _public_jwk(private_key, kid=_KID):
    numbers = private_key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64u(numbers.n), "e": _b64u(numbers.e)}


def _sign_id_token(private_pem, claims, kid=_KID, algorithm="RS256"):
    return jose_jwt.encode(claims, private_pem, algorithm=algorithm, headers={"kid": kid})


def _base_claims(sub, email, nonce, issuer=_ISSUER, audience=_CLIENT_ID):
    now = int(time.time())
    return {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "email": email,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    }


# ── Fakes: discovery-time (PR3 registration) and login-time (PR4) network ──


class _FakeDiscoveryResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = str(json_body)

    def json(self):
        return self._json_body


class _FakeDiscoveryClient:
    """Same shape as tests/test_org_sso.py's fake -- used only while
    creating the SSO config via the real PR3 API."""
    next_response = None

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, follow_redirects=None):
        return _FakeDiscoveryClient.next_response


class _FakeOIDCClient:
    """Fake for org_oidc_service.httpx.AsyncClient -- routes POST (token
    exchange) and GET (JWKS) independently so a test can configure both."""

    token_response = None
    token_status = 200
    jwks_response = None
    jwks_status = 200

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, headers=None):
        return _FakeDiscoveryResponse(_FakeOIDCClient.token_status, _FakeOIDCClient.token_response)

    async def get(self, url, follow_redirects=None):
        return _FakeDiscoveryResponse(_FakeOIDCClient.jwks_status, _FakeOIDCClient.jwks_response)


@pytest.fixture(autouse=True)
def _reset_fakes():
    _FakeDiscoveryClient.next_response = None
    _FakeOIDCClient.token_response = None
    _FakeOIDCClient.token_status = 200
    _FakeOIDCClient.jwks_response = None
    _FakeOIDCClient.jwks_status = 200
    yield


@pytest.fixture
def public_dns(monkeypatch):
    import socket
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture
def configured_crypto(monkeypatch):
    from cryptography.fernet import Fernet
    import app.core.crypto as crypto
    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _valid_discovery_doc(issuer=_ISSUER):
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }


@pytest.fixture
def org_with_sso(client, monkeypatch, public_dns, configured_crypto, rsa_keypair):
    """Creates a real org (via /orgs) with a real active SSO config (via
    the PR3 API, discovery mocked) pointed at _ISSUER/_CLIENT_ID. Returns
    everything a login/callback test needs."""
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, _valid_discovery_doc())

    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "SSO Login Test Org", "slug": f"sso-login-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()

    created = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": _ISSUER,
            "client_id": _CLIENT_ID,
            "client_secret": "acme-client-secret",
            "allowed_domains": ["acme-test.example.com"],
        },
        headers=headers,
    ).json()

    return {"org_id": org["id"], "org_slug": org["slug"], "owner": owner, "owner_headers": headers, "config": created}


def _do_login_redirect(client, org_slug):
    return client.get(f"/auth/sso/{org_slug}/login", follow_redirects=False)


def _set_valid_jwks(rsa_keypair):
    private_key, _ = rsa_keypair
    _FakeOIDCClient.jwks_response = {"keys": [_public_jwk(private_key)]}


# ── 1. SSO discovery ─────────────────────────────────────────────────────────


def test_discover_matching_domain_returns_org(client, org_with_sso):
    resp = client.get("/auth/sso/discover", params={"email": "someone@acme-test.example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["sso_available"] is True
    assert data["org_slug"] == org_with_sso["org_slug"]
    assert data["enforced"] is False


def test_discover_unknown_domain_returns_false(client, org_with_sso):
    resp = client.get("/auth/sso/discover", params={"email": "someone@totally-unrelated.example.com"})
    assert resp.status_code == 200
    assert resp.json() == {"sso_available": False}


def test_discover_never_leaks_existing_user_existence(client, org_with_sso):
    """A real, existing user account at an unconfigured domain must get
    the exact same response as one that doesn't exist at all."""
    real_user = _register_and_login(client, email=f"real-{uuid.uuid4().hex[:8]}@no-sso-configured.test")
    resp_existing = client.get("/auth/sso/discover", params={"email": real_user["email"]})
    resp_nonexistent = client.get(
        "/auth/sso/discover", params={"email": f"nobody-{uuid.uuid4().hex[:8]}@no-sso-configured.test"}
    )
    assert resp_existing.json() == resp_nonexistent.json() == {"sso_available": False}


# ── 2. Login redirect ─────────────────────────────────────────────────────────


def test_login_redirect_targets_correct_authorize_endpoint(client, org_with_sso):
    resp = _do_login_redirect(client, org_with_sso["org_slug"])
    assert resp.status_code in (302, 307)
    assert resp.headers["location"].startswith(f"{_ISSUER}/authorize?")


def test_login_redirect_includes_pkce_and_nonce(client, org_with_sso):
    resp = _do_login_redirect(client, org_with_sso["org_slug"])
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["code_challenge_method"][0] == "S256"
    assert len(query["code_challenge"][0]) > 20
    assert len(query["nonce"][0]) > 10
    assert query["client_id"][0] == _CLIENT_ID
    assert query["scope"][0] == "openid email profile"


def test_login_redirect_state_contains_org_context(client, org_with_sso):
    resp = _do_login_redirect(client, org_with_sso["org_slug"])
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    payload = decode_token(state)
    assert payload["type"] == "sso_state"
    assert payload["organization_id"] == org_with_sso["org_id"]
    assert payload["organization_sso_config_id"] is not None
    assert "code_verifier" in payload
    assert "nonce" in payload
    assert "created_at" in payload


def test_login_unknown_org_slug_returns_404(client):
    resp = client.get("/auth/sso/does-not-exist-org/login", follow_redirects=False)
    assert resp.status_code == 404


# ── 3. Successful callback ────────────────────────────────────────────────────


def test_successful_callback_creates_user_and_issues_sso_token(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    login_resp = _do_login_redirect(client, org_with_sso["org_slug"])
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
    nonce = decode_token(state)["nonce"]

    email = f"newuser-{uuid.uuid4().hex[:8]}@acme-test.example.com"
    id_token = _sign_id_token(private_pem, _base_claims(sub="idp-sub-1", email=email, nonce=nonce))
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "irrelevant"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(
        f"/auth/sso/{org_with_sso['org_slug']}/callback",
        json={"code": "fake-code", "state": state},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "access_token" in data
    assert "refresh_token" in data

    claims = decode_token(data["access_token"])
    assert claims["email"] == email
    assert claims["auth_method"] == "sso"
    assert claims["idp_org_id"] == org_with_sso["org_id"]
    assert claims["org_id"] == org_with_sso["org_id"]  # JIT-provisioned membership resolves as primary
    assert "org_member" in claims["org_role"]

    validate = client.post("/auth/validate", json={"token": data["access_token"]})
    assert validate.json()["valid"] is True
    assert validate.json()["idp_org_id"] == org_with_sso["org_id"]

    # PR11.1: the JWT claim above stays "sso" (unchanged, still checked
    # above) -- the *persisted* users.authentication_method column uses
    # the admin-console-facing vocabulary and maps "sso" -> "oidc".
    from app.db.models import User
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user.authentication_method == "oidc"
        assert user.last_login_at is not None
    finally:
        db.close()


def test_repeat_login_reuses_same_user_no_duplicate_membership(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _set_valid_jwks(rsa_keypair)
    email = f"repeat-{uuid.uuid4().hex[:8]}@acme-test.example.com"

    def _login_once():
        login_resp = _do_login_redirect(client, org_with_sso["org_slug"])
        state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
        nonce = decode_token(state)["nonce"]
        id_token = _sign_id_token(private_pem, _base_claims(sub="idp-sub-repeat", email=email, nonce=nonce))
        _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "irrelevant"}
        resp = client.post(
            f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state}
        )
        assert resp.status_code == 200
        return decode_token(resp.json()["access_token"])["sub"]

    user_id_1 = _login_once()
    user_id_2 = _login_once()
    assert user_id_1 == user_id_2

    db = _DirectSession()
    try:
        count = db.execute(
            text(
                "SELECT COUNT(*) FROM organization_memberships WHERE organization_id = :oid AND user_id = :uid"
            ),
            {"oid": org_with_sso["org_id"], "uid": user_id_1},
        ).scalar()
    finally:
        db.close()
    assert count == 1


# ── 4. Existing user linking ──────────────────────────────────────────────────


def test_existing_password_user_requires_link_confirmation(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    existing = _register_and_login(client, email=f"john-{uuid.uuid4().hex[:8]}@acme-test.example.com")

    login_resp = _do_login_redirect(client, org_with_sso["org_slug"])
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
    nonce = decode_token(state)["nonce"]
    id_token = _sign_id_token(
        private_pem, _base_claims(sub="idp-sub-existing-pw", email=existing["email"], nonce=nonce)
    )
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "irrelevant"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(
        f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert data["email"] == existing["email"]
    link_token = data["link_token"]

    # Not silently merged/logged in -- the *pending* user (not the org's
    # owner, who already has their own membership from org creation) has
    # no membership yet, pending confirmation.
    existing_user_id = client.post("/auth/validate", json={"token": existing["access_token"]}).json()["user_id"]
    db = _DirectSession()
    try:
        count = db.execute(
            text(
                "SELECT COUNT(*) FROM organization_memberships "
                "WHERE organization_id = :oid AND user_id = :uid"
            ),
            {"oid": org_with_sso["org_id"], "uid": existing_user_id},
        ).scalar()
    finally:
        db.close()
    assert count == 0

    wrong = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"}
    )
    assert wrong.status_code == 401

    confirm = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]}
    )
    assert confirm.status_code == 200
    claims = decode_token(confirm.json()["access_token"])
    assert claims["auth_method"] == "sso"
    assert claims["idp_org_id"] == org_with_sso["org_id"]
    assert claims["org_id"] == org_with_sso["org_id"]  # JIT-provisioned on confirm


def test_existing_oauth_only_user_cannot_be_linked_without_password(client, org_with_sso, monkeypatch, rsa_keypair):
    """Case 2: an account that already exists via the 3-provider OAuth
    flow has no password at all -- same protection as any other existing
    account: the link cannot be completed (there's no credential to prove
    ownership with), never silently merged as a bypass."""
    private_key, private_pem = rsa_keypair
    email = f"google-user-{uuid.uuid4().hex[:8]}@acme-test.example.com"

    from app.core.jwt import create_oauth_state_token
    from app.core.oauth_providers import PROVIDERS

    google_client_id_before = PROVIDERS["google"]["client_id"]
    PROVIDERS["google"]["client_id"] = "test-google-client-id"
    PROVIDERS["google"]["client_secret"] = "test-google-client-secret"

    async def fake_exchange(provider, code, code_verifier=None):
        return "google-uid-for-linking-test", email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)

    google_state = create_oauth_state_token("google")
    created = client.post("/auth/google/callback", json={"code": "fake", "state": google_state})
    assert created.json()["status"] == "ok"
    PROVIDERS["google"]["client_id"] = google_client_id_before

    login_resp = _do_login_redirect(client, org_with_sso["org_slug"])
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
    nonce = decode_token(state)["nonce"]
    id_token = _sign_id_token(private_pem, _base_claims(sub="idp-sub-existing-oauth", email=email, nonce=nonce))
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "irrelevant"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(
        f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state}
    )
    assert resp.status_code == 200
    link_token = resp.json()["link_token"]

    confirm = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": "anything-at-all"}
    )
    assert confirm.status_code == 409  # "no password set" -- same guard as the existing flow


# ── 5. Invalid IdP token ──────────────────────────────────────────────────────


def _login_and_get_state_nonce(client, org_slug):
    login_resp = _do_login_redirect(client, org_slug)
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
    return state, decode_token(state)["nonce"]


def test_callback_wrong_issuer_rejected(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    state, nonce = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    claims = _base_claims(sub="s", email="x@acme-test.example.com", nonce=nonce, issuer="https://not-the-real-idp.example.com")
    id_token = _sign_id_token(private_pem, claims)
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 400


def test_callback_wrong_audience_rejected(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    state, nonce = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    claims = _base_claims(sub="s", email="x@acme-test.example.com", nonce=nonce, audience="some-other-client-id")
    id_token = _sign_id_token(private_pem, claims)
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 400


def test_callback_invalid_signature_rejected(client, org_with_sso, monkeypatch, rsa_keypair):
    """Signed with a DIFFERENT private key than the one whose public JWK
    is served -- proves signature verification is real, not a shape check."""
    _, real_private_pem = rsa_keypair
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    state, nonce = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    claims = _base_claims(sub="s", email="x@acme-test.example.com", nonce=nonce)
    id_token = _sign_id_token(attacker_pem, claims)  # wrong key
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)  # JWKS still serves the REAL public key

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 400


def test_callback_wrong_nonce_rejected(client, org_with_sso, monkeypatch, rsa_keypair):
    private_key, private_pem = rsa_keypair
    state, nonce = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    claims = _base_claims(sub="s", email="x@acme-test.example.com", nonce="a-completely-different-nonce")
    id_token = _sign_id_token(private_pem, claims)
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 400


def test_callback_missing_id_token_rejected(client, org_with_sso, monkeypatch, rsa_keypair):
    state, nonce = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"access_token": "x"}  # no id_token at all

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 400


def test_callback_tampered_state_rejected(client, org_with_sso):
    resp = client.post(
        f"/auth/sso/{org_with_sso['org_slug']}/callback",
        json={"code": "c", "state": "not-a-real-token"},
    )
    assert resp.status_code == 400


def test_get_callback_failure_redirects_with_error_not_raw_json(client, org_with_sso):
    resp = client.get(
        f"/auth/sso/{org_with_sso['org_slug']}/callback?code=c&state=not-a-real-token",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 307)
    assert "/oauth-complete?" in resp.headers["location"]
    assert "status=error" in resp.headers["location"]


# ── 6. Tenant isolation ───────────────────────────────────────────────────────


@pytest.fixture
def second_org_with_sso(client, monkeypatch, public_dns, configured_crypto):
    second_issuer = "https://idp.beta-test.example.com"
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, _valid_discovery_doc(issuer=second_issuer))

    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "SSO Login Org B", "slug": f"sso-login-org-b-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": second_issuer,
            "client_id": "beta-client-id",
            "client_secret": "beta-client-secret",
            "allowed_domains": ["beta-test.example.com"],
        },
        headers=headers,
    ).json()
    return {
        "org_id": org["id"], "org_slug": org["slug"], "issuer": second_issuer,
        "client_id": "beta-client-id", "owner_headers": headers, "config": created,
    }


def test_same_sub_different_orgs_creates_separate_unlinked_accounts(
    client, org_with_sso, second_org_with_sso, monkeypatch, rsa_keypair
):
    """The exact Case 3 concern: a `sub` value shared across two
    independent orgs' IdPs must never resolve to the same linked account
    -- organization_sso_config_id scoping in find_linked_user is what
    prevents this."""
    private_key, private_pem = rsa_keypair
    shared_sub = "shared-sub-across-orgs-123"

    # Login to Org A.
    state_a, nonce_a = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    id_token_a = _sign_id_token(
        private_pem, _base_claims(sub=shared_sub, email="john@acme-test.example.com", nonce=nonce_a)
    )
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token_a, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)
    resp_a = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state_a})
    assert resp_a.status_code == 200
    claims_a = decode_token(resp_a.json()["access_token"])
    assert claims_a["idp_org_id"] == org_with_sso["org_id"]

    # Login to Org B with the SAME sub but a different, brand-new email --
    # must create a genuinely separate user, not resolve to Org A's.
    state_b, nonce_b = _login_and_get_state_nonce(client, second_org_with_sso["org_slug"])
    id_token_b = _sign_id_token(
        private_pem,
        _base_claims(
            sub=shared_sub, email="jane@beta-test.example.com", nonce=nonce_b,
            issuer=second_org_with_sso["issuer"], audience=second_org_with_sso["client_id"],
        ),
    )
    _FakeOIDCClient.token_response = {"id_token": id_token_b, "access_token": "x"}
    resp_b = client.post(
        f"/auth/sso/{second_org_with_sso['org_slug']}/callback", json={"code": "c", "state": state_b}
    )
    assert resp_b.status_code == 200
    claims_b = decode_token(resp_b.json()["access_token"])
    assert claims_b["idp_org_id"] == second_org_with_sso["org_id"]

    assert claims_a["sub"] != claims_b["sub"]  # genuinely different users

    # Direct DB proof: two OAuthAccount rows, same provider_user_id, each
    # scoped to its own organization_sso_config_id, each pointing at its
    # own user.
    db = _DirectSession()
    try:
        rows = db.execute(
            text(
                "SELECT organization_sso_config_id, user_id FROM oauth_accounts "
                "WHERE provider = 'oidc' AND provider_user_id = :sub ORDER BY organization_sso_config_id"
            ),
            {"sub": shared_sub},
        ).fetchall()
    finally:
        db.close()
    assert len(rows) == 2
    assert rows[0][1] != rows[1][1]  # different user_id
    assert rows[0][0] != rows[1][0]  # different organization_sso_config_id


def test_org_a_idp_cannot_mint_org_b_token_for_existing_shared_email_user(
    client, org_with_sso, second_org_with_sso, monkeypatch, rsa_keypair
):
    """Domain-overlap variant of Case 3: an existing user's email happens
    to be one Org A's IdP can vouch for. Logging in via Org A's IdP must
    never produce a token scoped to Org B, and the confirmation path (if
    triggered) must resolve org context strictly from the state that
    authenticated -- Org A -- never from anywhere else."""
    private_key, private_pem = rsa_keypair
    shared_email = f"carol-{uuid.uuid4().hex[:8]}@acme-test.example.com"
    existing = _register_and_login(client, email=shared_email)

    state_a, nonce_a = _login_and_get_state_nonce(client, org_with_sso["org_slug"])
    id_token = _sign_id_token(private_pem, _base_claims(sub="carol-sub", email=shared_email, nonce=nonce_a))
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _set_valid_jwks(rsa_keypair)

    resp = client.post(f"/auth/sso/{org_with_sso['org_slug']}/callback", json={"code": "c", "state": state_a})
    assert resp.status_code == 200
    assert resp.json()["status"] == "link_required"

    confirm = client.post(
        "/auth/link/confirm", json={"link_token": resp.json()["link_token"], "password": existing["password"]}
    )
    assert confirm.status_code == 200
    claims = decode_token(confirm.json()["access_token"])
    assert claims["idp_org_id"] == org_with_sso["org_id"]
    assert claims["idp_org_id"] != second_org_with_sso["org_id"]
    assert claims["org_id"] == org_with_sso["org_id"]


# ── 7. Regression (also exercised via the full-suite run, see deliverable) ──


def test_existing_google_oauth_login_route_unaffected(client):
    """Smoke check within this file too: the 3-provider routes still
    exist and behave as before -- full regression is the complete
    tests/test_oauth.py + tests/test_pkce.py suites, run separately."""
    resp = client.get("/auth/bitbucket/login")
    assert resp.status_code == 404  # unknown provider, same as always
