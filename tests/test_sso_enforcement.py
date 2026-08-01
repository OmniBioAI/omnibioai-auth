"""Phase 2 PR5: org-enforced SSO cutover. The one PR in this phase with
real behavior change for *existing* users' *existing* login attempts --
strictly opt-in per org (an admin must explicitly set enforced=true, and
only after the lockout guard is satisfied).
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

from app.core.jwt import decode_token
from app.services import oauth_service, org_oidc_service, org_sso_service

_CLIENT_ID = "enforce-client-id"
_KID = "enforce-test-key-1"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"enforce-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
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


def _sign_id_token(private_pem, claims, kid=_KID):
    return jose_jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def _base_claims(sub, email, nonce, issuer):
    now = int(time.time())
    return {"iss": issuer, "aud": _CLIENT_ID, "sub": sub, "email": email, "nonce": nonce, "iat": now, "exp": now + 300}


# ── Fakes (same shapes as test_org_sso.py / test_sso_login.py) ─────────────


class _FakeResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = str(json_body)

    def json(self):
        return self._json_body


class _FakeDiscoveryClient:
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
    token_response = None
    jwks_response = None

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, headers=None):
        return _FakeResponse(200, _FakeOIDCClient.token_response)

    async def get(self, url, follow_redirects=None):
        return _FakeResponse(200, _FakeOIDCClient.jwks_response)


@pytest.fixture(autouse=True)
def _reset_fakes():
    _FakeDiscoveryClient.next_response = None
    _FakeOIDCClient.token_response = None
    _FakeOIDCClient.jwks_response = None
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


def _valid_discovery_doc(issuer):
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }


@pytest.fixture
def org_with_sso(client, monkeypatch, public_dns, configured_crypto):
    # Unique issuer/domain per test invocation -- test.db persists across
    # the whole session (conftest.py's `client` fixture is session-scoped),
    # so a fixed domain reused by every test in this file would let a
    # *later* test's domain-matching lookup accidentally resolve to an
    # *earlier* test's config instead of its own (most of which have
    # enforced=False) -- exactly the kind of cross-test collision this
    # file's own enforcement assertions would otherwise silently get wrong.
    unique = uuid.uuid4().hex[:8]
    issuer = f"https://idp.enforce-test-{unique}.example.com"
    domain = f"enforce-test-{unique}.example.com"

    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeResponse(200, _valid_discovery_doc(issuer))

    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "Enforcement Test Org", "slug": f"enforce-org-{unique}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": issuer,
            "client_id": _CLIENT_ID,
            "client_secret": "enforce-client-secret",
            "allowed_domains": [domain],
        },
        headers=headers,
    ).json()
    return {
        "org_id": org["id"], "org_slug": org["slug"], "owner": owner, "owner_headers": headers,
        "config": created, "issuer": issuer, "domain": domain,
    }


def _complete_one_sso_login(client, monkeypatch, rsa_keypair, org, sub=None, email=None):
    """Drives a full, real login through /auth/sso -- this is how the
    lockout guard gets satisfied (an actual OAuthAccount row must exist),
    same mechanism as tests/test_sso_login.py."""
    private_key, private_pem = rsa_keypair
    sub = sub or f"sub-{uuid.uuid4().hex[:8]}"
    email = email or f"member-{uuid.uuid4().hex[:8]}@{org['domain']}"

    login_resp = client.get(f"/auth/sso/{org['org_slug']}/login", follow_redirects=False)
    state = parse_qs(urlparse(login_resp.headers["location"]).query)["state"][0]
    nonce = decode_token(state)["nonce"]

    id_token = _sign_id_token(private_pem, _base_claims(sub, email, nonce, org["issuer"]))
    monkeypatch.setattr(org_oidc_service.httpx, "AsyncClient", _FakeOIDCClient)
    _FakeOIDCClient.token_response = {"id_token": id_token, "access_token": "x"}
    _FakeOIDCClient.jwks_response = {"keys": [_public_jwk(private_key)]}

    resp = client.post(f"/auth/sso/{org['org_slug']}/callback", json={"code": "c", "state": state})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    return resp, email


# ── Lockout guard ────────────────────────────────────────────────────────────


def test_enforced_true_rejected_without_prior_sso_login(client, org_with_sso):
    resp = client.patch(
        f"/orgs/{org_with_sso['org_id']}/sso", json={"enforced": True}, headers=org_with_sso["owner_headers"]
    )
    assert resp.status_code == 400
    assert "at least one member" in resp.json()["detail"]

    check = client.get(f"/orgs/{org_with_sso['org_id']}/sso", headers=org_with_sso["owner_headers"])
    assert check.json()["enforced"] is False


def test_enforced_true_succeeds_after_a_completed_sso_login(client, org_with_sso, monkeypatch, rsa_keypair):
    _complete_one_sso_login(client, monkeypatch, rsa_keypair, org_with_sso)

    resp = client.patch(
        f"/orgs/{org_with_sso['org_id']}/sso", json={"enforced": True}, headers=org_with_sso["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["enforced"] is True


def _enable_enforcement(client, monkeypatch, rsa_keypair, org):
    _complete_one_sso_login(client, monkeypatch, rsa_keypair, org)
    resp = client.patch(f"/orgs/{org['org_id']}/sso", json={"enforced": True}, headers=org["owner_headers"])
    assert resp.status_code == 200
    return resp.json()


# ── Password login rejection, without ever checking the password ──────────


def test_password_login_rejected_without_calling_verify_password(client, org_with_sso, monkeypatch, rsa_keypair):
    # Registered (and logged in once, successfully) *before* enforcement
    # is turned on -- this is an existing password account that predates
    # the org enforcing SSO, exactly the case enforcement must still catch.
    member = _register_and_login(client, email=f"carol-{uuid.uuid4().hex[:8]}@{org_with_sso['domain']}")
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    call_count = {"n": 0}
    real_verify = None
    import app.services.auth_service as auth_service_module

    def spy_verify_password(*args, **kwargs):
        call_count["n"] += 1
        return True  # would incorrectly succeed if ever reached

    monkeypatch.setattr(auth_service_module, "verify_password", spy_verify_password)

    resp = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "sso_required"
    assert detail["org_slug"] == org_with_sso["org_slug"]
    assert detail["sso_login_url"] == f"/auth/sso/{org_with_sso['org_slug']}/login"
    assert call_count["n"] == 0  # verify_password never reached


def test_password_login_still_works_with_wrong_domain_email(client, org_with_sso, monkeypatch, rsa_keypair):
    """Sanity: enforcement is domain-scoped, an unrelated email at the
    same org's admin flow is unaffected."""
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)
    outsider = _register_and_login(client, email=f"outside-{uuid.uuid4().hex[:8]}@totally-different.test")
    resp = client.post("/auth/login", json={"email": outsider["email"], "password": outsider["password"]})
    assert resp.status_code == 200


# ── Not bypassable via Google/GitHub/Microsoft ──────────────────────────────


def test_google_oauth_login_rejected_for_enforced_org_member(client, org_with_sso, monkeypatch, rsa_keypair):
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    from app.core.jwt import create_oauth_state_token
    from app.core.oauth_providers import PROVIDERS

    PROVIDERS["google"]["client_id"] = "test-google-client-id"
    PROVIDERS["google"]["client_secret"] = "test-google-client-secret"

    email = f"dave-{uuid.uuid4().hex[:8]}@{org_with_sso['domain']}"

    async def fake_exchange(provider, code, code_verifier=None):
        return "google-uid-enforce-bypass-attempt", email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)

    state = create_oauth_state_token("google")
    resp = client.post("/auth/google/callback", json={"code": "fake", "state": state})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sso_required"


def test_get_callback_redirect_carries_sso_required_reason_as_query_params(client, org_with_sso, monkeypatch, rsa_keypair):
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    from app.core.jwt import create_oauth_state_token
    from app.core.oauth_providers import PROVIDERS

    PROVIDERS["google"]["client_id"] = "test-google-client-id"
    PROVIDERS["google"]["client_secret"] = "test-google-client-secret"
    email = f"erin-{uuid.uuid4().hex[:8]}@{org_with_sso['domain']}"

    async def fake_exchange(provider, code, code_verifier=None):
        return "google-uid-enforce-get", email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)

    state = create_oauth_state_token("google")
    resp = client.get(f"/auth/google/callback?code=fake&state={state}", follow_redirects=False)
    assert resp.status_code in (302, 307)
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["status"][0] == "error"
    assert query["reason"][0] == "sso_required"
    assert query["org_slug"][0] == org_with_sso["org_slug"]


# ── Tenant isolation ──────────────────────────────────────────────────────────


@pytest.fixture
def second_org_not_enforced(client, monkeypatch, public_dns, configured_crypto):
    second_issuer = "https://idp.other-org-test.example.com"
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeResponse(
        200,
        {
            "issuer": second_issuer,
            "authorization_endpoint": f"{second_issuer}/authorize",
            "token_endpoint": f"{second_issuer}/token",
            "jwks_uri": f"{second_issuer}/jwks",
        },
    )
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "Non-Enforcing Org", "slug": f"non-enforce-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": second_issuer, "client_id": "other-client-id", "client_secret": "s",
            "allowed_domains": ["other-org-test.example.com"],
        },
        headers=headers,
    )
    return {"org_id": org["id"], "org_slug": org["slug"]}


def test_non_enforced_org_user_unaffected_by_other_orgs_enforcement(
    client, org_with_sso, second_org_not_enforced, monkeypatch, rsa_keypair
):
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    member = _register_and_login(client, email=f"frank-{uuid.uuid4().hex[:8]}@other-org-test.example.com")
    resp = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp.status_code == 200  # unaffected -- different org, never enforced


# ── Break-glass override ────────────────────────────────────────────────────


def test_override_requires_global_permission_not_org_admin(client, org_with_sso, monkeypatch, rsa_keypair):
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    resp = client.post(
        f"/orgs/{org_with_sso['org_id']}/sso/override",
        json={"reason": "IdP outage"},
        headers=org_with_sso["owner_headers"],  # org admin, not global admin
    )
    assert resp.status_code == 403


def test_override_bypasses_enforcement_and_clear_restores_it(
    client, org_with_sso, admin_headers, monkeypatch, rsa_keypair
):
    member = _register_and_login(client, email=f"grace-{uuid.uuid4().hex[:8]}@{org_with_sso['domain']}")
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    blocked = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert blocked.status_code == 403

    override = client.post(
        f"/orgs/{org_with_sso['org_id']}/sso/override",
        json={"reason": "IdP outage, unblocking pending fix"},
        headers=admin_headers,
    )
    assert override.status_code == 200
    assert override.json()["enforced"] is True  # org's own setting untouched
    assert override.json()["sso_override_active"] is True

    unblocked = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert unblocked.status_code == 200

    cleared = client.delete(f"/orgs/{org_with_sso['org_id']}/sso/override", headers=admin_headers)
    assert cleared.status_code == 200
    assert cleared.json()["sso_override_active"] is False

    reblocked = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert reblocked.status_code == 403


def test_override_is_recorded_with_reason_and_actor(client, org_with_sso, admin_headers, monkeypatch, rsa_keypair):
    """"Logged/auditable" in this repo (no external audit sink exists --
    see Phase 1's design doc and PR3/PR4's own outcome notes) means
    durably persisted with who/why/when, retrievable via the API --
    verified here rather than just asserted."""
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    direct_engine = create_engine("sqlite:///./test.db")
    DirectSession = sessionmaker(bind=direct_engine)

    client.post(
        f"/orgs/{org_with_sso['org_id']}/sso/override",
        json={"reason": "scheduled IdP maintenance window"},
        headers=admin_headers,
    )

    db = DirectSession()
    try:
        row = db.execute(
            text(
                "SELECT sso_override_reason, sso_override_by_user_id, sso_override_at "
                "FROM organization_sso_configs WHERE organization_id = :oid"
            ),
            {"oid": org_with_sso["org_id"]},
        ).fetchone()
    finally:
        db.close()

    assert row[0] == "scheduled IdP maintenance window"
    assert row[1] is not None
    assert row[2] is not None


# ── enforced can always be turned back off ──────────────────────────────────


def test_enforced_can_be_disabled_without_the_lockout_guard(client, org_with_sso, monkeypatch, rsa_keypair):
    _enable_enforcement(client, monkeypatch, rsa_keypair, org_with_sso)

    resp = client.patch(
        f"/orgs/{org_with_sso['org_id']}/sso", json={"enforced": False}, headers=org_with_sso["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["enforced"] is False

    member = _register_and_login(client, email=f"henry-{uuid.uuid4().hex[:8]}@{org_with_sso['domain']}")
    resp2 = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp2.status_code == 200
