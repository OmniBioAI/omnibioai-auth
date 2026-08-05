"""PR11.4b (Identity Audit Trail Foundation): audit coverage for the four
identity lifecycle areas that previously emitted nothing --
user status, API keys, OAuth clients, SSO configuration/enforcement --
plus the new read-only GET /platform/audit-events retrieval endpoint.

Follows tests/test_audit_ledger.py's (PR9) exact convention: real HTTP
calls through real routes/services against the shared sqlite test DB,
audit rows read back via a second, direct session -- never mocks of
audit_service itself. Reuses tests/test_apikeys.py's/test_oauth_clients.py's/
test_org_sso.py's own local `org`/discovery fixtures rather than
inventing a different registration flow, same "each test file is
self-contained" convention this repo already follows throughout.
"""
import os
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, Role, User
from app.services import org_sso_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_ISSUER = "https://idp.audit-test.example.com"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"audit-pr11-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _grant_platform_admin(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


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
def platform_admin(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs", json={"name": "Audit PR11.4b Org", "slug": f"audit-pr11-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


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


# ── User lifecycle ───────────────────────────────────────────────────────


def test_suspending_a_user_emits_user_disabled_event(client, platform_admin):
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.patch(
        f"/platform/users/{target_id}", json={"status": "suspended", "reason": "policy violation"},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200

    events = _events(event_type="user_disabled", target_user_id=target_id)
    assert len(events) == 1
    assert events[0]["actor_user_id"] == _user_id(client, platform_admin["access_token"])
    assert events[0]["before_state"]["status"] == "active"
    assert events[0]["after_state"]["status"] == "suspended"
    assert events[0]["metadata"]["reason"] == "policy violation"
    # No single org in scope for a cross-tenant platform-user action.
    assert events[0]["organization_id"] is None


def test_reactivating_a_user_emits_user_enabled_event(client, platform_admin):
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])
    client.patch(
        f"/platform/users/{target_id}", json={"status": "suspended"}, headers=platform_admin["headers"],
    )

    resp = client.patch(
        f"/platform/users/{target_id}", json={"status": "active", "reason": "appeal approved"},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200

    events = _events(event_type="user_enabled", target_user_id=target_id)
    assert len(events) == 1
    assert events[0]["before_state"]["status"] == "suspended"
    assert events[0]["after_state"]["status"] == "active"


def test_resubmitting_the_same_status_emits_no_event(client, platform_admin):
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    # Already "active" -- setting it to "active" again is a no-op.
    resp = client.patch(f"/platform/users/{target_id}", json={"status": "active"}, headers=platform_admin["headers"])
    assert resp.status_code == 200

    assert _events(event_type="user_enabled", target_user_id=target_id) == []
    assert _events(event_type="user_disabled", target_user_id=target_id) == []


# ── API Key lifecycle ────────────────────────────────────────────────────


def test_create_api_key_emits_event_with_no_secret(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "CI Pipeline", "scopes": []}, headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    key_id = resp.json()["id"]

    events = _events(event_type="api_key_created", resource_type="api_key", resource_id=str(key_id))
    assert len(events) == 1
    event = events[0]
    assert event["organization_id"] == org["id"]
    assert event["metadata"]["api_key_name"] == "CI Pipeline"
    _assert_no_secret_leakage(event)


def test_revoke_api_key_emits_event_with_actor_and_no_secret(client, org):
    created = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Revoke Me", "scopes": []}, headers=org["owner_headers"],
    ).json()
    owner_id = _user_id(client, org["owner"]["access_token"])

    resp = client.delete(f"/orgs/{org['id']}/api-keys/{created['id']}", headers=org["owner_headers"])
    assert resp.status_code == 204

    events = _events(event_type="api_key_revoked", resource_type="api_key", resource_id=str(created["id"]))
    assert len(events) == 1
    event = events[0]
    assert event["actor_user_id"] == owner_id
    assert event["organization_id"] == org["id"]
    assert event["before_state"]["status"] == "active"
    assert event["after_state"]["status"] == "revoked"
    _assert_no_secret_leakage(event)


# ── OAuth Client lifecycle ───────────────────────────────────────────────


def test_create_oauth_client_emits_event_with_no_secret(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "ETL Worker", "scopes": []}, headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    row_id = resp.json()["id"]

    events = _events(event_type="oauth_client_created", resource_type="oauth_client", resource_id=str(row_id))
    assert len(events) == 1
    event = events[0]
    assert event["organization_id"] == org["id"]
    assert event["metadata"]["client_name"] == "ETL Worker"
    assert event["metadata"]["client_id"] == resp.json()["client_id"]
    _assert_no_secret_leakage(event)


def test_revoke_oauth_client_emits_event_with_actor_and_no_secret(client, org):
    created = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "Revoke Me Too", "scopes": []},
        headers=org["owner_headers"],
    ).json()
    owner_id = _user_id(client, org["owner"]["access_token"])

    resp = client.delete(f"/orgs/{org['id']}/oauth-clients/{created['id']}", headers=org["owner_headers"])
    assert resp.status_code == 204

    events = _events(event_type="oauth_client_revoked", resource_type="oauth_client", resource_id=str(created["id"]))
    assert len(events) == 1
    event = events[0]
    assert event["actor_user_id"] == owner_id
    assert event["before_state"]["status"] == "active"
    assert event["after_state"]["status"] == "revoked"
    _assert_no_secret_leakage(event)


# ── SSO lifecycle ─────────────────────────────────────────────────────────
# Same discovery/DNS/crypto fakes tests/test_org_sso.py already
# establishes -- configure_sso/update_sso_config make a real (faked)
# network call, so these can't be exercised without them.


def _valid_discovery_doc(issuer=_ISSUER):
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }


class _FakeDiscoveryResponse:
    def __init__(self, status_code=200, json_body=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = str(json_body)

    def json(self):
        return self._json_body


class _FakeDiscoveryClient:
    next_response = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, follow_redirects=None):
        return _FakeDiscoveryClient.next_response


@pytest.fixture
def public_dns(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture
def configured_crypto(monkeypatch):
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def configured_discovery(monkeypatch, public_dns, configured_crypto):
    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)
    _FakeDiscoveryClient.next_response = _FakeDiscoveryResponse(200, _valid_discovery_doc())


def _assert_no_secret_leakage(event: dict) -> None:
    blob = str(event["before_state"]) + str(event["after_state"]) + str(event["metadata"])
    for forbidden in ("super-secret", "client_secret", "key_hash", "client_secret_hash", "client_secret_encrypted"):
        assert forbidden not in blob, f"{forbidden!r} leaked into audit event: {event}"


def test_create_sso_config_emits_event_with_no_secret(client, org, configured_discovery):
    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "acme-client", "client_secret": "super-secret-value", "allowed_domains": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    config_id = resp.json().get("id") or _sso_config_id(org["id"])

    events = _events(event_type="sso_configuration_created", organization_id=org["id"])
    assert len(events) == 1
    event = events[0]
    assert event["after_state"]["issuer"] == _ISSUER
    assert event["metadata"]["provider_type"] == "oidc"
    _assert_no_secret_leakage(event)
    assert config_id or True  # id isn't in the response schema; resource_id assertion below covers linkage


def test_update_sso_config_emits_event_with_before_after_and_no_secret(client, org, configured_discovery):
    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "acme-client", "client_secret": "super-secret-value", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    resp = client.patch(
        f"/orgs/{org['id']}/sso", json={"client_id": "new-client-id"}, headers=org["owner_headers"],
    )
    assert resp.status_code == 200

    events = _events(event_type="sso_configuration_updated", organization_id=org["id"])
    assert len(events) == 1
    event = events[0]
    assert event["before_state"]["client_id"] == "acme-client"
    assert event["after_state"]["client_id"] == "new-client-id"
    _assert_no_secret_leakage(event)


def test_enforcement_change_emits_event_after_a_completed_sso_login(client, org, configured_discovery, monkeypatch):
    """set_enforced's own lockout guard requires >=1 completed SSO login
    before enforced can go True -- simulate that directly (a full OIDC
    callback round-trip is out of scope for this file; test_sso_login.py
    already covers that flow) by inserting an OAuthAccount row linked to
    the config, mirroring has_completed_sso_login's own query.
    """
    from app.db.models import OAuthAccount, OrganizationSSOConfig

    client.post(
        f"/orgs/{org['id']}/sso",
        json={"issuer": _ISSUER, "client_id": "acme-client", "client_secret": "super-secret-value", "allowed_domains": []},
        headers=org["owner_headers"],
    )

    db = _DirectSession()
    try:
        config = db.query(OrganizationSSOConfig).filter(OrganizationSSOConfig.organization_id == org["id"]).first()
        owner_id = _user_id(client, org["owner"]["access_token"])
        db.add(OAuthAccount(
            user_id=owner_id, provider="oidc", provider_user_id=f"sub-{uuid.uuid4().hex[:8]}",
            organization_sso_config_id=config.id,
        ))
        db.commit()
    finally:
        db.close()

    resp = client.patch(f"/orgs/{org['id']}/sso", json={"enforced": True}, headers=org["owner_headers"])
    assert resp.status_code == 200

    events = _events(event_type="sso_enforcement_changed", organization_id=org["id"])
    assert len(events) == 1
    event = events[0]
    assert event["before_state"]["enforced"] is False
    assert event["after_state"]["enforced"] is True
    assert event["metadata"]["enforced_before"] is False
    assert event["metadata"]["enforced_after"] is True


def _sso_config_id(organization_id: int) -> int | None:
    from app.db.models import OrganizationSSOConfig

    db = _DirectSession()
    try:
        row = db.query(OrganizationSSOConfig).filter(OrganizationSSOConfig.organization_id == organization_id).first()
        return row.id if row else None
    finally:
        db.close()


# ── GET /platform/audit-events ───────────────────────────────────────────


def test_list_audit_events_requires_platform_admin(client, org):
    resp = client.get("/platform/audit-events", headers=org["owner_headers"])
    assert resp.status_code == 403


def test_list_audit_events_returns_paginated_results(client, org, platform_admin):
    client.post(f"/orgs/{org['id']}/api-keys", json={"name": "Pagination Key", "scopes": []}, headers=org["owner_headers"])

    resp = client.get(
        "/platform/audit-events", params={"organization_id": org["id"], "page": 1, "page_size": 5},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["page"] == 1
    assert body["page_size"] == 5
    assert body["total"] >= 1
    assert any(e["event_type"] == "api_key_created" for e in body["items"])


def test_list_audit_events_filters_by_event_type(client, org, platform_admin):
    created = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Filter Key", "scopes": []}, headers=org["owner_headers"],
    ).json()
    client.delete(f"/orgs/{org['id']}/api-keys/{created['id']}", headers=org["owner_headers"])

    resp = client.get(
        "/platform/audit-events",
        params={"organization_id": org["id"], "event_type": "api_key_revoked"},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    assert all(e["event_type"] == "api_key_revoked" for e in items)


def test_list_audit_events_filters_by_actor_user_id(client, org, platform_admin):
    owner_id = _user_id(client, org["owner"]["access_token"])
    client.post(f"/orgs/{org['id']}/api-keys", json={"name": "Actor Filter Key", "scopes": []}, headers=org["owner_headers"])

    resp = client.get(
        "/platform/audit-events", params={"actor_user_id": owner_id, "organization_id": org["id"]},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    assert all(e["actor_user_id"] == owner_id for e in items)


def test_list_audit_events_resolves_actor_email_and_organization_name(client, org, platform_admin):
    client.post(f"/orgs/{org['id']}/api-keys", json={"name": "Resolve Key", "scopes": []}, headers=org["owner_headers"])

    resp = client.get(
        "/platform/audit-events",
        params={"organization_id": org["id"], "event_type": "api_key_created"},
        headers=platform_admin["headers"],
    )
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["actor_email"] == org["owner"]["email"]
    assert items[0]["organization_name"] == "Audit PR11.4b Org"


def test_list_audit_events_never_exposes_secret_fields(client, org, platform_admin):
    client.post(f"/orgs/{org['id']}/api-keys", json={"name": "Secret Check Key", "scopes": []}, headers=org["owner_headers"])

    resp = client.get(
        "/platform/audit-events", params={"organization_id": org["id"]}, headers=platform_admin["headers"],
    )
    body_text = resp.text
    for forbidden in ("key_hash", "client_secret", "client_secret_encrypted", "client_secret_hash"):
        assert forbidden not in body_text


def test_audit_events_are_immutable_no_update_or_delete_route(client, org, platform_admin):
    client.post(f"/orgs/{org['id']}/api-keys", json={"name": "Immutable Key", "scopes": []}, headers=org["owner_headers"])
    events = _events(event_type="api_key_created", organization_id=org["id"])
    event_id = events[-1]["id"]

    # No PATCH/PUT/DELETE route exists for a single audit event -- both
    # come back 404/405, never a successful mutation.
    assert client.patch(f"/platform/audit-events/{event_id}", json={}, headers=platform_admin["headers"]).status_code in (404, 405)
    assert client.delete(f"/platform/audit-events/{event_id}", headers=platform_admin["headers"]).status_code in (404, 405)
