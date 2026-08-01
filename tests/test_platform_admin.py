"""Phase 3 PR0.4: platform_admin foundation.

Covers app/rbac.py's get_org_membership_or_platform_admin/
require_org_permission_or_platform_admin -- the global `manage_all_orgs`
permission (never the role name "platform_admin") that lets a platform
admin reach any organization's data, while every non-platform-admin
caller's behavior is provably unchanged (locked in by PR0.3's own
regression suite, re-verified here for the routes this PR actually
touches: organizations, teams, API keys, OAuth clients, SSO config).
"""
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Role, User
from app.rbac import get_org_membership_or_platform_admin

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pa-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _make_org(client, owner, name):
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _grant_platform_admin(email: str) -> None:
    """Assigns the platform_admin role directly via DB -- mirrors PR0.2's
    role-grant test pattern. Relies on app.main's startup sequence having
    already run ensure_platform_admin_role (it has, by the time `client`
    is first used, since app.main is imported at conftest.py's module
    load time), so the `platform_admin` Role/`manage_all_orgs` Permission
    rows already exist; this only assigns the role to a specific user.
    """
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin(client):
    """A user granted platform_admin, logged in *after* the grant so their
    JWT's `permissions` claim actually carries manage_all_orgs -- a role
    granted mid-session never retroactively updates an already-issued
    token (the same reasoning PR0.2's role-removal test exercises in the
    opposite direction)."""
    user = _register_and_login(client)
    _grant_platform_admin(user["email"])
    relogged = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    return {**user, **relogged.json(), "headers": _auth_header(relogged.json()["access_token"])}


# ── A. Platform admin can cross tenant boundaries ───────────────────────────


def test_platform_admin_can_view_org_they_are_not_a_member_of(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "PA Foreign Org")

    resp = client.get(f"/orgs/{org['id']}", headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["id"] == org["id"]


def test_platform_admin_leaves_no_real_membership_trace(client):
    """The bypass must never create a persisted organization_memberships
    row -- a platform admin viewing a foreign org must not appear in that
    org's real member list."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "PA No Trace Org")

    view = client.get(f"/orgs/{org['id']}", headers=admin["headers"])
    assert view.status_code == 200

    members = client.get(f"/orgs/{org['id']}/members", headers=org["owner_headers"]).json()
    assert not any(m["email"] == admin["email"] for m in members)


def test_platform_admin_can_create_team_in_foreign_org(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "PA Teams Org")

    resp = client.post(
        f"/orgs/{org['id']}/teams", json={"name": "Support Team"}, headers=admin["headers"]
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "Support Team"

    # Real, visible to the org's own owner too -- not a phantom response.
    listed = client.get(f"/orgs/{org['id']}/teams", headers=org["owner_headers"]).json()
    assert any(t["name"] == "Support Team" for t in listed)


def test_platform_admin_can_create_api_key_in_foreign_org(client):
    """Exercises the synthetic membership's `.roles` -- create_api_key
    calls org_service.permissions_for_membership(membership) to validate
    the requested scopes against the caller's own permissions. A platform
    admin must resolve to the real org_admin permission set here, not an
    empty one, or this would 400 for every scope."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "PA API Keys Org")

    resp = client.post(
        f"/orgs/{org['id']}/api-keys",
        json={"name": "PA-created key", "scopes": ["manage_teams"]},
        headers=admin["headers"],
    )
    assert resp.status_code == 201


def test_platform_admin_can_manage_sso_config_in_foreign_org(client, monkeypatch):
    """Exercises routes_org_sso.py's platform-admin-gated CRUD, mirroring
    tests/test_org_sso.py's own fakes for discovery/DNS/encryption -- see
    that file's configured_discovery fixture, reimplemented inline here
    since fixtures in a non-conftest test module aren't shared across
    files in this repo's test layout.
    """
    import socket

    import httpx
    from cryptography.fernet import Fernet

    import app.core.crypto as crypto
    from app.services import org_sso_service

    issuer = "https://idp.pa-sso-test.example.com"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(org_sso_service.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/token",
                "jwks_uri": f"{issuer}/jwks",
            }

    class _FakeDiscoveryClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, follow_redirects=None):
            return _FakeResponse()

    monkeypatch.setattr(org_sso_service.httpx, "AsyncClient", _FakeDiscoveryClient)

    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "PA SSO Org")

    resp = client.post(
        f"/orgs/{org['id']}/sso",
        json={
            "issuer": issuer,
            "client_id": "pa-test-client",
            "client_secret": "pa-test-secret",
            "allowed_domains": ["pa-sso-test.example.com"],
        },
        headers=admin["headers"],
    )
    assert resp.status_code == 201


# ── B. Normal users cannot cross tenant boundaries via this change ─────────


def test_org_admin_without_manage_all_orgs_still_blocked_from_other_org(client):
    owner_a = _register_and_login(client)
    org_a = _make_org(client, owner_a, "Normal Org A")
    owner_b = _register_and_login(client)
    org_b = _make_org(client, owner_b, "Normal Org B")

    # owner_b is a real, legitimate org_admin -- just not of org_a.
    resp = client.get(f"/orgs/{org_a['id']}", headers=org_b["owner_headers"])
    assert resp.status_code == 404

    resp2 = client.post(
        f"/orgs/{org_a['id']}/teams", json={"name": "Should not work"}, headers=org_b["owner_headers"]
    )
    assert resp2.status_code == 404


def test_non_member_still_receives_404(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner, "Outsider Test Org")
    outsider = _register_and_login(client)

    resp = client.get(f"/orgs/{org['id']}", headers=_auth_header(outsider["access_token"]))
    assert resp.status_code == 404


# ── C. Service identities cannot use manage_all_orgs ────────────────────────


def test_client_credentials_token_rejected_before_platform_admin_check_runs(client):
    """End-to-end: even if a client_credentials token existed, it must
    never reach the bypass logic at all -- get_current_user's existing
    rejection (Phase 2 PR1) fires first."""
    owner = _register_and_login(client)
    org = _make_org(client, owner, "Service Identity Org")
    oc = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "svc", "scopes": ["manage_teams"]},
        headers=org["owner_headers"],
    ).json()

    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    service_token = token_resp.json()["access_token"]

    other_owner = _register_and_login(client)
    other_org = _make_org(client, other_owner, "Another Org")

    resp = client.get(f"/orgs/{other_org['id']}", headers=_auth_header(service_token))
    assert resp.status_code == 401


def test_hand_crafted_client_credentials_payload_cannot_use_bypass(client):
    """Unit-level defense-in-depth: get_org_membership_or_platform_admin's
    own auth_method guard must reject a payload shaped like a service
    token even if manage_all_orgs somehow appeared in its permissions --
    this can't happen via the real token-issuance code path (OAuthClient
    scopes are never Permission rows), but the guard exists so this
    function's own safety doesn't depend solely on get_current_user never
    changing upstream."""
    owner = _register_and_login(client)
    org = _make_org(client, owner, "Guard Test Org")

    db = _DirectSession()
    try:
        fake_service_payload = {
            "sub": "1",
            "auth_method": "client_credentials",
            "permissions": ["manage_all_orgs"],
        }
        with pytest.raises(HTTPException) as exc:
            get_org_membership_or_platform_admin(org_id=org["id"], db=db, user=fake_service_payload)
        # Falls through to the real membership check, which 404s -- not a
        # crash, and not access granted.
        assert exc.value.status_code == 404
    finally:
        db.close()


# ── D. Fail closed ───────────────────────────────────────────────────────────


def test_platform_admin_check_error_falls_back_to_real_membership_check(client, monkeypatch):
    """If resolving the bypass itself raises for any reason, the caller
    must fall through to the ordinary membership check -- never crash,
    never grant access on an incomplete resolution."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner, "Fail Closed Org")

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated failure resolving the org_admin role")

    monkeypatch.setattr("app.rbac.role_service.get_role_by_name", _boom)

    resp = client.get(f"/orgs/{org['id']}", headers=admin["headers"])
    # Still a real, legitimate platform_admin permission -- but the
    # resolution path errored, so this must fail closed to the ordinary
    # 404 a non-member gets, never a 500 and never a 200.
    assert resp.status_code == 404


def test_platform_admin_gets_404_not_500_for_nonexistent_org(client):
    admin = _platform_admin(client)
    resp = client.get("/orgs/999999999", headers=admin["headers"])
    assert resp.status_code == 404


# ── PR0.2 x PR0.4 integration: manage_all_orgs is refresh-fresh, not just
# login-fresh -- the specific guarantee that motivated shipping PR0.2
# (refresh rebuilds claims from the database) before PR0.4 (a real,
# usable global permission) in the remediation plan's own ordering. ──────


def test_granting_platform_admin_takes_effect_on_refresh_not_just_relogin(client):
    from app.core.jwt import decode_token

    user = _register_and_login(client)
    assert "manage_all_orgs" not in decode_token(user["access_token"]).get("permissions", [])

    _grant_platform_admin(user["email"])

    refreshed = client.post("/auth/refresh", json={"refresh_token": user["refresh_token"]}).json()
    assert "manage_all_orgs" in decode_token(refreshed["access_token"])["permissions"]

    other_owner = _register_and_login(client)
    other_org = _make_org(client, other_owner, "Refresh Grant Org")
    resp = client.get(f"/orgs/{other_org['id']}", headers=_auth_header(refreshed["access_token"]))
    assert resp.status_code == 200


def test_revoking_platform_admin_takes_effect_on_refresh(client):
    admin = _platform_admin(client)

    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == admin["email"]).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        user.roles.remove(role)
        db.commit()
    finally:
        db.close()

    from app.core.jwt import decode_token

    refreshed = client.post("/auth/refresh", json={"refresh_token": admin["refresh_token"]}).json()
    assert "manage_all_orgs" not in decode_token(refreshed["access_token"])["permissions"]

    other_owner = _register_and_login(client)
    other_org = _make_org(client, other_owner, "Refresh Revoke Org")
    resp = client.get(f"/orgs/{other_org['id']}", headers=_auth_header(refreshed["access_token"]))
    assert resp.status_code == 404
