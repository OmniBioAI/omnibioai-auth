"""Phase 2 PR3: per-org OIDC IdP registration -- admin CRUD only. No login
path exists yet (Phase 2 PR4); this whole feature is inert until then.
"""

import os
import socket
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.services import org_sso_service

# Same physical file conftest.py's `client` fixture uses -- a second
# connection opened directly so tests can assert on raw column values
# (e.g. "the database never contains plaintext"), same convention as
# tests/test_apikeys.py.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_ISSUER = "https://idp.acme-test.example.com"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"orgsso-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    resp = client.post("/auth/validate", json={"token": access_token})
    return resp.json()["user_id"]


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


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Org SSO Test Org", "slug": f"org-sso-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _valid_discovery_doc(issuer=_ISSUER):
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }


# ── Fakes: no real network or DNS resolution in these tests ────────────────


class _FakeDiscoveryResponse:
    def __init__(self, status_code=200, json_body=None, raise_json_error=False):
        self.status_code = status_code
        self._json_body = json_body
        self._raise_json_error = raise_json_error
        self.text = str(json_body)

    def json(self):
        if self._raise_json_error:
            raise ValueError("not valid json")
        return self._json_body


class _FakeDiscoveryClient:
    """Configurable fake for httpx.AsyncClient -- discovery is GET-only.
    Set `next_response` (a _FakeDiscoveryResponse) or `next_exception`
    (an httpx.HTTPError instance) before the call under test."""

    next_response = None
    next_exception = None
    captured_url = None
    captured_follow_redirects = "unset"

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, follow_redirects=None):
        _FakeDiscoveryClient.captured_url = url
        _FakeDiscoveryClient.captured_follow_redirects = follow_redirects
        if _FakeDiscoveryClient.next_exception is not None:
            raise _FakeDiscoveryClient.next_exception
        return _FakeDiscoveryClient.next_response


@pytest.fixture(autouse=True)
def _reset_fake_discovery_client():
    _FakeDiscoveryClient.next_response = None
    _FakeDiscoveryClient.next_exception = None
    _FakeDiscoveryClient.captured_url = None
    yield


@pytest.fixture
def public_dns(monkeypatch):
    """Makes the SSRF pre-flight resolve _ISSUER's host to a public IP,
    without touching real DNS -- deterministic and network-free, same
    reasoning as faking httpx below."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_config.py's fixture of the same name:
    conftest.py never sets CONFIG_ENCRYPTION_KEY, and app.core.crypto's
    Fernet instance is computed once at import time, so patch the
    already-imported module's singleton directly rather than the env var."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def configured_discovery(monkeypatch, public_dns, configured_crypto):
    """The full happy-path double: public DNS + a valid discovery document
    + a working encryption key."""
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, _valid_discovery_doc())


# ── 1. Successful discovery ─────────────────────────────────────────────────


def test_create_sso_config_success(client, org, configured_discovery):
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": _ISSUER,
            "client_id": "acme-client-id",
            "client_secret": "super-secret-value",
            "allowed_domains": ["acme.test"],
        },
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["issuer"] == _ISSUER
    assert data["client_id"] == "acme-client-id"
    assert data["provider_type"] == "oidc"
    assert data["allowed_domains"] == ["acme.test"]
    assert data["status"] == "active"
    assert "client_secret" not in data
    assert "client_secret_encrypted" not in data


def test_created_secret_is_encrypted_not_plaintext(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": _ISSUER,
            "client_id": "acme-client-id",
            "client_secret": "super-secret-value",
            "allowed_domains": [],
        },
        headers=org["owner_headers"],
    )

    db = _DirectSession()
    try:
        row = db.execute(
            text("SELECT client_secret_encrypted FROM organization_sso_configs WHERE organization_id = :oid"),
            {"oid": org["id"]},
        ).fetchone()
    finally:
        db.close()

    assert row is not None
    encrypted_value = row[0]
    assert encrypted_value != "super-secret-value"
    assert "super-secret-value" not in encrypted_value


def test_create_sso_config_stores_discovery_endpoints(client, org, configured_discovery):
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201

    db = _DirectSession()
    try:
        row = db.execute(
            text(
                "SELECT authorization_endpoint, token_endpoint, jwks_uri, last_verified_at "
                "FROM organization_sso_configs WHERE organization_id = :oid"
            ),
            {"oid": org["id"]},
        ).fetchone()
    finally:
        db.close()

    assert row[0] == f"{_ISSUER}/authorize"
    assert row[1] == f"{_ISSUER}/token"
    assert row[2] == f"{_ISSUER}/jwks"
    assert row[3] is not None  # last_verified_at set on successful discovery


# ── 2. Discovery failures -- 400, nothing persisted ─────────────────────────


def _assert_nothing_persisted(client, org, headers):
    check = client.get(f"/orgs/{org['id']}/sso", headers=headers)
    assert check.status_code == 404


def test_discovery_unreachable_rejected(client, org, public_dns, monkeypatch):
    import httpx

    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_exception = httpx.ConnectError("connection refused")

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_discovery_invalid_json_rejected(client, org, public_dns, monkeypatch):
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, raise_json_error=True)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_discovery_non_200_rejected(client, org, public_dns, monkeypatch):
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(404, {})

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


@pytest.mark.parametrize("missing_field", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
def test_discovery_missing_required_field_rejected(client, org, public_dns, monkeypatch, missing_field):
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    doc = _valid_discovery_doc()
    del doc[missing_field]
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, doc)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    assert missing_field in resp.json()["detail"]
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_discovery_issuer_mismatch_rejected(client, org, public_dns, monkeypatch):
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    doc = _valid_discovery_doc(issuer="https://not-the-requested-issuer.example.com")
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, doc)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    assert "issuer" in resp.json()["detail"].lower()
    _assert_nothing_persisted(client, org, org["owner_headers"])


# ── SSRF / issuer validation ─────────────────────────────────────────────────


def test_issuer_resolving_to_private_ip_rejected(client, org, monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_issuer_resolving_to_loopback_rejected(client, org, monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_issuer_resolving_to_cloud_metadata_link_local_rejected(client, org, monkeypatch):
    """169.254.169.254 -- the AWS/GCP/Azure instance-metadata address, the
    single most consequential SSRF target this check exists to block."""
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_issuer_unresolvable_host_rejected(client, org, monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror("nodename nor servname provided, or not known")
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_http_issuer_rejected_by_default(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": "http://idp.acme-test.example.com",  # not https
            "client_id": "cid",
            "client_secret": "secret",
            "allowed_domains": [],
        },
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    _assert_nothing_persisted(client, org, org["owner_headers"])


def test_non_http_scheme_issuer_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": "ftp://example.com", "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


# ── 3. Permissions ───────────────────────────────────────────────────────────


def test_org_admin_with_manage_sso_can_create(client, org, configured_discovery):
    # org_owner created the org, so holds org_admin -> manage_sso via
    # ensure_org_admin_permissions' self-healing top-up (same mechanism
    # Phase 2 PR1 introduced).
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201


def test_member_without_manage_sso_receives_403(client, org, configured_discovery, admin_headers):
    owner_id = _user_id(client, org["owner"]["access_token"])

    # Downgrade the org owner from org_admin to a custom role that holds
    # manage_org (needed to make this very API call) but deliberately not
    # manage_sso -- same technique test_orgs.py's escalation-guard test uses.
    # Role creation itself needs the *global* manage_roles permission
    # (require_permission, JWT-claim-based), which only admin@omnibioai
    # holds -- org_admin's org-scoped permissions don't cover it.
    narrow_role = f"org-sso-narrow-{uuid.uuid4().hex[:8]}"
    client.post(
        "/roles",
        json={"name": narrow_role, "permissions": ["manage_org"]},
        headers=admin_headers,
    )
    downgrade = client.put(
        f"/orgs/{org['id']}/members/{owner_id}/roles",
        json={"roles": [narrow_role]},
        headers=org["owner_headers"],
    )
    assert downgrade.status_code == 200

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 403


def test_missing_token_rejected(client, org):
    resp = client.get(f"/orgs/{org['id']}/sso")
    assert resp.status_code in (401, 403)


# ── 4. Secret handling ───────────────────────────────────────────────────────


def test_get_never_returns_secret(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "super-secret-value", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    resp = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert resp.status_code == 200
    body = resp.json()
    serialized = str(body)
    assert "super-secret-value" not in serialized
    assert "client_secret" not in body
    assert "client_secret_encrypted" not in body


# ── 5. Organization isolation ────────────────────────────────────────────────


def test_org_a_cannot_view_org_b_sso_config(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs",
        json={"name": "Org B", "slug": f"org-sso-org-b-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    ).json()

    resp = client.get(f"/orgs/{org['id']}/sso", headers=other_headers)
    assert resp.status_code == 404

    resp2 = client.get(f"/orgs/{other_org['id']}/sso", headers=org["owner_headers"])
    assert resp2.status_code == 404  # org B has no config either, but this also proves no cross-org leak


def test_org_a_cannot_update_or_delete_org_b_sso_config(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    client.post(
        "/orgs",
        json={"name": "Org C", "slug": f"org-sso-org-c-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    )

    update = client.patch(
        f"/orgs/{org['id']}/sso",
        json={"client_id": "hijacked"},
        headers=other_headers,
    )
    assert update.status_code == 404

    delete = client.delete(f"/orgs/{org['id']}/sso", headers=other_headers)
    assert delete.status_code == 404

    # Confirm the original config is untouched.
    still_there = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert still_there.json()["client_id"] == "cid"


# ── 6. One IdP per organization ──────────────────────────────────────────────


def test_second_sso_config_for_same_org_rejected(client, org, configured_discovery):
    first = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid-1", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert first.status_code == 201

    second = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid-2", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert second.status_code == 409

    # Original config untouched by the rejected second attempt.
    check = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert check.json()["client_id"] == "cid-1"


# ── Update / delete happy paths ──────────────────────────────────────────────


def test_update_allowed_domains_without_rerunning_discovery(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": ["a.test"]},
        headers=org["owner_headers"],
    )
    # Discovery client now returns nothing useful -- proves an
    # allowed_domains-only update doesn't re-trigger discovery at all.
    _FakeDiscoveryClient.next_exception = Exception("must not be called")

    resp = client.patch(
        f"/orgs/{org['id']}/sso",
        json={"allowed_domains": ["a.test", "b.test"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["allowed_domains"] == ["a.test", "b.test"]


def test_update_issuer_reruns_discovery(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    new_issuer = "https://idp2.acme-test.example.com"
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, _valid_discovery_doc(issuer=new_issuer))

    resp = client.patch(
        f"/orgs/{org['id']}/sso",
        json={"issuer": new_issuer},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["issuer"] == new_issuer


def test_update_issuer_failed_discovery_leaves_existing_config_untouched(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(500, {})
    resp = client.patch(
        f"/orgs/{org['id']}/sso",
        json={"issuer": "https://broken-idp.example.com"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400

    unchanged = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert unchanged.json()["issuer"] == _ISSUER


def test_delete_sso_config(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "cid", "client_secret": "secret", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    resp = client.delete(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert resp.status_code == 204

    check = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert check.status_code == 404


def test_get_sso_config_404_when_none_exists(client, org):
    resp = client.get(f"/orgs/{org['id']}/sso", headers=org["owner_headers"])
    assert resp.status_code == 404
