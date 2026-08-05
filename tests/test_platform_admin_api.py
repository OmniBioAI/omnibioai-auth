"""Phase 3 PR1: /platform/orgs and /platform/orgs/{org_id} -- the platform-
admin organization discovery API. Every route here is gated by
require_permission(MANAGE_ALL_ORGS) only (no org membership, no synthetic
membership -- see routes_platform_admin.py's own comment on why this is
deliberately different from PR0.4's require_org_permission_or_platform_admin).
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import LicenseKey, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pa-api-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _make_org(client, owner, name=None):
    name = name or f"Platform API Org {uuid.uuid4().hex[:6]}"
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "name": name, "owner": owner, "owner_headers": headers}


def _grant_platform_admin(email: str) -> None:
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
    user = _register_and_login(client)
    _grant_platform_admin(user["email"])
    relogged = client.post("/auth/login", json={"email": user["email"], "password": user["password"]}).json()
    return {**user, **relogged, "headers": _auth_header(relogged["access_token"])}


# ── A. Basic listing / detail ───────────────────────────────────────────────


def test_platform_admin_can_list_organizations(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get("/platform/orgs", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert any(item["id"] == org["id"] for item in body["items"])
    listed = next(item for item in body["items"] if item["id"] == org["id"])
    assert listed["owner_email"] == owner["email"]
    assert listed["member_count"] >= 1  # creator is auto-added as org_admin
    assert listed["team_count"] == 0
    assert listed["api_key_count"] == 0
    assert listed["oauth_client_count"] == 0
    assert listed["license_count"] == 0
    assert listed["sso_enabled"] is False
    # PR11.5.6: same computed-boolean shape as sso_enabled -- no
    # OrganizationMFAPolicy row exists yet for this org.
    assert listed["mfa_policy_required"] is False
    assert listed["mfa_policy_configured"] is False
    # Never a nested list -- summaries only.
    assert "members" not in listed and "teams" not in listed


def test_platform_orgs_list_never_includes_nested_members_or_teams(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/orgs", headers=admin["headers"])
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert set(item.keys()) == {
            "id", "name", "status", "created_at", "owner_email", "member_count",
            "team_count", "api_key_count", "oauth_client_count", "license_count", "sso_enabled",
            "mfa_policy_required", "mfa_policy_configured",
        }


def test_mfa_policy_required_reflects_a_real_required_policy(client):
    """PR11.5.6: mfa_policy_required is True only once an
    OrganizationMFAPolicy row with required=True exists (PR11.5.5's own
    POST /orgs/{org_id}/mfa-policy, unmodified) -- not a new policy
    concept invented by this endpoint."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    created = client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    assert created.status_code == 201

    resp = client.get("/platform/orgs", headers=admin["headers"])
    listed = next(item for item in resp.json()["items"] if item["id"] == org["id"])
    assert listed["mfa_policy_required"] is True
    assert listed["mfa_policy_configured"] is True


def test_mfa_policy_configured_true_even_when_not_required(client):
    """PR11.5.6: mfa_policy_configured and mfa_policy_required are
    distinct -- a policy row with required=False has been configured,
    just not turned on."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    created = client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"])
    assert created.status_code == 201

    resp = client.get("/platform/orgs", headers=admin["headers"])
    listed = next(item for item in resp.json()["items"] if item["id"] == org["id"])
    assert listed["mfa_policy_required"] is False
    assert listed["mfa_policy_configured"] is True


def test_organization_detail_endpoint_reflects_real_resources(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    client.post(f"/orgs/{org['id']}/teams", json={"name": "Wet Lab"}, headers=org["owner_headers"])
    client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "CI key", "scopes": []}, headers=org["owner_headers"]
    )
    client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "svc", "scopes": []}, headers=org["owner_headers"]
    )

    db = _DirectSession()
    try:
        db.add(LicenseKey(key="OMNI-TEST-0000-0000-0001", email=owner["email"], organization_id=org["id"]))
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/platform/orgs/{org['id']}", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()

    assert body["id"] == org["id"]
    assert body["owner_email"] == owner["email"]
    assert body["member_summary"]["total"] == 1
    assert body["member_summary"]["active"] == 1
    assert body["team_summary"]["total"] == 1
    assert body["api_key_summary"]["total"] == 1
    assert body["api_key_summary"]["active"] == 1
    assert body["oauth_client_summary"]["total"] == 1
    assert body["license_summary"]["total"] == 1
    assert body["license_summary"]["active"] == 1
    assert body["sso"]["configured"] is False
    assert body["recent_activity"]["org_created_at"] is not None


def test_detail_endpoint_is_read_only_no_mutation_routes_exist(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    for method in ("post", "put", "patch", "delete"):
        resp = getattr(client, method)(f"/platform/orgs/{org['id']}", headers=admin["headers"])
        assert resp.status_code == 405


def test_nonexistent_organization_returns_404(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/orgs/999999999", headers=admin["headers"])
    assert resp.status_code == 404


def test_existing_org_scoped_endpoints_untouched(client):
    """/orgs/... stays exactly as it was -- /platform/orgs is additive,
    not a replacement or an overload of the existing surface."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    resp = client.get(f"/orgs/{org['id']}", headers=org["owner_headers"])
    assert resp.status_code == 200
    assert "member_count" not in resp.json()  # unchanged OrganizationOut shape


# ── B. Pagination ────────────────────────────────────────────────────────────


def test_pagination_page_size_and_total(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    marker = uuid.uuid4().hex[:8]
    for i in range(5):
        _make_org(client, owner, f"Pagination Org {marker}-{i}")

    resp = client.get(
        "/platform/orgs", params={"page": 1, "page_size": 2, "search": f"Pagination Org {marker}"},
        headers=admin["headers"],
    )
    body = resp.json()
    assert body["total"] == 5
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["total_pages"] == 3
    assert len(body["items"]) == 2

    page2 = client.get(
        "/platform/orgs", params={"page": 2, "page_size": 2, "search": f"Pagination Org {marker}"},
        headers=admin["headers"],
    ).json()
    assert len(page2["items"]) == 2
    assert {i["id"] for i in body["items"]}.isdisjoint({i["id"] for i in page2["items"]})

    page_beyond_end = client.get(
        "/platform/orgs", params={"page": 99, "page_size": 2, "search": f"Pagination Org {marker}"},
        headers=admin["headers"],
    ).json()
    assert page_beyond_end["items"] == []
    assert page_beyond_end["total"] == 5


def test_page_size_capped(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/orgs", params={"page_size": 10000}, headers=admin["headers"])
    assert resp.status_code == 422  # Query(..., le=100)


# ── C. Search ────────────────────────────────────────────────────────────────


def test_search_matches_organization_name(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    unique = uuid.uuid4().hex[:10]
    org = _make_org(client, owner, f"Zebra-{unique}")

    resp = client.get("/platform/orgs", params={"search": unique}, headers=admin["headers"])
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == org["id"]


def test_search_matches_owner_email(client):
    admin = _platform_admin(client)
    unique = uuid.uuid4().hex[:10]
    owner = _register_and_login(client, email=f"owner-{unique}@omnibioai.test")
    org = _make_org(client, owner)

    resp = client.get("/platform/orgs", params={"search": unique}, headers=admin["headers"])
    body = resp.json()
    assert any(item["id"] == org["id"] for item in body["items"])


def test_search_no_match_returns_empty(client):
    admin = _platform_admin(client)
    resp = client.get(
        "/platform/orgs", params={"search": f"nonexistent-{uuid.uuid4().hex}"}, headers=admin["headers"]
    )
    body = resp.json()
    assert body["total"] == 0
    assert body["items"] == []


# ── D. Sorting ───────────────────────────────────────────────────────────────


def test_sort_by_name_ascending(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    marker = uuid.uuid4().hex[:8]
    _make_org(client, owner, f"{marker}-Bravo")
    _make_org(client, owner, f"{marker}-Alpha")
    _make_org(client, owner, f"{marker}-Charlie")

    resp = client.get(
        "/platform/orgs",
        params={"search": marker, "sort_by": "name", "sort_order": "asc", "page_size": 100},
        headers=admin["headers"],
    )
    names = [item["name"] for item in resp.json()["items"]]
    assert names == sorted(names)


def test_sort_by_created_at_descending_is_default(client):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    marker = uuid.uuid4().hex[:8]
    first = _make_org(client, owner, f"{marker}-first")
    second = _make_org(client, owner, f"{marker}-second")

    resp = client.get("/platform/orgs", params={"search": marker}, headers=admin["headers"])
    ids_in_order = [item["id"] for item in resp.json()["items"]]
    assert ids_in_order.index(second["id"]) < ids_in_order.index(first["id"])


def test_invalid_sort_by_rejected(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/orgs", params={"sort_by": "member_count"}, headers=admin["headers"])
    assert resp.status_code == 422


# ── E. Authorization / token lifecycle ──────────────────────────────────────


def test_non_platform_admin_forbidden(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)  # owner is a real org_admin, just not a platform_admin

    resp = client.get("/platform/orgs", headers=org["owner_headers"])
    assert resp.status_code == 403

    resp2 = client.get(f"/platform/orgs/{org['id']}", headers=org["owner_headers"])
    assert resp2.status_code == 403


def test_revoked_token_rejected(client):
    admin = _platform_admin(client)
    assert client.get("/platform/orgs", headers=admin["headers"]).status_code == 200

    client.post(
        "/auth/logout",
        json={"refresh_token": admin["refresh_token"], "access_token": admin["access_token"]},
    )

    resp = client.get("/platform/orgs", headers=admin["headers"])
    assert resp.status_code == 401


def test_suspended_account_rejected(client):
    admin = _platform_admin(client)
    assert client.get("/platform/orgs", headers=admin["headers"]).status_code == 200

    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == admin["email"]).first()
        user.status = "suspended"
        db.commit()
    finally:
        db.close()

    resp = client.get("/platform/orgs", headers=admin["headers"])
    assert resp.status_code == 401


def test_client_credentials_token_rejected(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    oc = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "svc", "scopes": []}, headers=org["owner_headers"]
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

    resp = client.get("/platform/orgs", headers=_auth_header(service_token))
    assert resp.status_code == 401


def test_platform_admin_bypass_not_used_no_synthetic_membership_needed(client):
    """A platform admin must see an org they are not a member of, without
    any org_id in the request at all for the list endpoint -- proving
    this route doesn't depend on PR0.4's per-org synthetic-membership
    bypass, only the flat global permission."""
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get("/platform/orgs", headers=admin["headers"])
    assert any(item["id"] == org["id"] for item in resp.json()["items"])

    detail = client.get(f"/platform/orgs/{org['id']}", headers=admin["headers"])
    assert detail.status_code == 200
