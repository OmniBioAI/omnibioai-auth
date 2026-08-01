"""Phase 3 PR3A: /platform/users -- the platform-admin user directory.
Every route here is gated by require_permission(MANAGE_ALL_ORGS) only --
the same permission PR1's org directory and PR0.4's org bypass already
use (see routes_platform_users.py's own comment on this choice).
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pu-api-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _make_org(client, owner, name=None):
    name = name or f"Platform User API Org {uuid.uuid4().hex[:6]}"
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
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


# ── A. Basic listing / detail ───────────────────────────────────────────────


def test_platform_admin_can_list_users(client):
    admin = _platform_admin(client)
    someone = _register_and_login(client)

    resp = client.get("/platform/users", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert any(item["email"] == someone["email"] for item in body["items"])


def test_platform_users_list_is_lightweight_summaries_only(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/users", headers=admin["headers"])
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert set(item.keys()) == {"id", "email", "status", "created_at", "global_roles", "org_count"}
        assert "memberships" not in item


def test_user_detail_shows_org_memberships(client):
    admin = _platform_admin(client)
    member = _register_and_login(client)

    org_a = _make_org(client, _register_and_login(client), "Membership Org A")
    org_b = _make_org(client, _register_and_login(client), "Membership Org B")
    client.post(f"/orgs/{org_a['id']}/invite", json={"email": member["email"]}, headers=org_a["owner_headers"])
    client.post(f"/orgs/{org_b['id']}/invite", json={"email": member["email"]}, headers=org_b["owner_headers"])

    resp = client.post("/auth/validate", json={"token": member["access_token"]})
    member_id = resp.json()["user_id"]

    detail = client.get(f"/platform/users/{member_id}", headers=admin["headers"])
    assert detail.status_code == 200
    body = detail.json()
    assert body["email"] == member["email"]
    assert len(body["memberships"]) == 2
    org_names = {m["organization_name"] for m in body["memberships"]}
    assert org_names == {"Membership Org A", "Membership Org B"}
    for m in body["memberships"]:
        assert m["roles"] == ["org_member"]
        assert m["status"] == "invited"


def test_user_detail_shows_global_roles(client):
    admin = _platform_admin(client)
    resp = client.post("/auth/validate", json={"token": admin["access_token"]})
    admin_id = resp.json()["user_id"]

    detail = client.get(f"/platform/users/{admin_id}", headers=admin["headers"])
    assert detail.status_code == 200
    assert "platform_admin" in detail.json()["global_roles"]


def test_nonexistent_user_returns_404(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/users/999999999", headers=admin["headers"])
    assert resp.status_code == 404


def test_existing_org_scoped_member_endpoint_untouched(client):
    """/orgs/{id}/members stays exactly as it was -- /platform/users is
    additive, not a replacement."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    resp = client.get(f"/orgs/{org['id']}/members", headers=org["owner_headers"])
    assert resp.status_code == 200
    assert "org_count" not in resp.json()[0]  # unchanged MemberOut shape


# ── B. Pagination / search / sort ───────────────────────────────────────────


def test_pagination_page_size_and_total(client):
    admin = _platform_admin(client)
    marker = uuid.uuid4().hex[:8]
    for i in range(5):
        _register_and_login(client, email=f"page-user-{marker}-{i}@omnibioai.test")

    resp = client.get(
        "/platform/users", params={"page": 1, "page_size": 2, "search": f"page-user-{marker}"},
        headers=admin["headers"],
    )
    body = resp.json()
    assert body["total"] == 5
    assert body["total_pages"] == 3
    assert len(body["items"]) == 2

    page2 = client.get(
        "/platform/users", params={"page": 2, "page_size": 2, "search": f"page-user-{marker}"},
        headers=admin["headers"],
    ).json()
    assert {i["id"] for i in body["items"]}.isdisjoint({i["id"] for i in page2["items"]})


def test_search_matches_email(client):
    admin = _platform_admin(client)
    unique = uuid.uuid4().hex[:10]
    someone = _register_and_login(client, email=f"searchable-{unique}@omnibioai.test")

    resp = client.get("/platform/users", params={"search": unique}, headers=admin["headers"])
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["email"] == someone["email"]


def test_sort_by_email_ascending(client):
    admin = _platform_admin(client)
    marker = uuid.uuid4().hex[:8]
    _register_and_login(client, email=f"{marker}-bravo@omnibioai.test")
    _register_and_login(client, email=f"{marker}-alpha@omnibioai.test")

    resp = client.get(
        "/platform/users",
        params={"search": marker, "sort_by": "email", "sort_order": "asc"},
        headers=admin["headers"],
    )
    emails = [item["email"] for item in resp.json()["items"]]
    assert emails == sorted(emails)


def test_invalid_sort_by_rejected(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/users", params={"sort_by": "org_count"}, headers=admin["headers"])
    assert resp.status_code == 422


# ── C. Authorization / token lifecycle ──────────────────────────────────────


def test_non_platform_admin_forbidden(client):
    owner = _register_and_login(client)
    resp = client.get("/platform/users", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 403


def test_revoked_token_rejected(client):
    admin = _platform_admin(client)
    assert client.get("/platform/users", headers=admin["headers"]).status_code == 200
    client.post(
        "/auth/logout",
        json={"refresh_token": admin["refresh_token"], "access_token": admin["access_token"]},
    )
    resp = client.get("/platform/users", headers=admin["headers"])
    assert resp.status_code == 401


def test_suspended_account_rejected(client):
    admin = _platform_admin(client)
    assert client.get("/platform/users", headers=admin["headers"]).status_code == 200
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == admin["email"]).first()
        user.status = "suspended"
        db.commit()
    finally:
        db.close()
    resp = client.get("/platform/users", headers=admin["headers"])
    assert resp.status_code == 401


def test_client_credentials_token_rejected(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    oc = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "svc", "scopes": []}, headers=org["owner_headers"]
    ).json()
    token_resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": oc["client_id"], "client_secret": oc["client_secret"]},
    )
    resp = client.get("/platform/users", headers=_auth_header(token_resp.json()["access_token"]))
    assert resp.status_code == 401


# ── D. Suspend / reactivate ──────────────────────────────────────────────────


def test_platform_admin_can_suspend_and_reactivate_user(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = client.post("/auth/validate", json={"token": target["access_token"]}).json()["user_id"]

    suspend = client.patch(
        f"/platform/users/{target_id}", json={"status": "suspended", "reason": "ToS violation"},
        headers=admin["headers"],
    )
    assert suspend.status_code == 200
    body = suspend.json()
    assert body["status"] == "suspended"
    assert body["status_changed_reason"] == "ToS violation"
    assert body["status_changed_by_email"] == admin["email"]

    reactivate = client.patch(
        f"/platform/users/{target_id}", json={"status": "active"}, headers=admin["headers"]
    )
    assert reactivate.status_code == 200
    assert reactivate.json()["status"] == "active"


def test_suspending_a_user_immediately_rejects_their_existing_token(client):
    """The cross-cutting proof this matters: unlike organization
    suspension (PR2 -- a display-only flag today), suspending a *user*
    takes effect immediately, because PR0.1's assert_token_usable already
    rejects any token for a non-"active" user. No new enforcement code
    was needed for this PR -- it's a direct consequence of PR0.1 already
    existing."""
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = client.post("/auth/validate", json={"token": target["access_token"]}).json()["user_id"]

    # Valid before suspension.
    assert client.get("/orgs", headers=_auth_header(target["access_token"])).status_code == 200

    client.patch(f"/platform/users/{target_id}", json={"status": "suspended"}, headers=admin["headers"])

    resp = client.get("/orgs", headers=_auth_header(target["access_token"]))
    assert resp.status_code == 401


def test_non_platform_admin_cannot_change_user_status(client):
    owner = _register_and_login(client)
    target = _register_and_login(client)
    target_id = client.post("/auth/validate", json={"token": target["access_token"]}).json()["user_id"]

    resp = client.patch(
        f"/platform/users/{target_id}", json={"status": "suspended"}, headers=_auth_header(owner["access_token"])
    )
    assert resp.status_code == 403


def test_invalid_status_value_rejected(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = client.post("/auth/validate", json={"token": target["access_token"]}).json()["user_id"]

    resp = client.patch(
        f"/platform/users/{target_id}", json={"status": "deleted"}, headers=admin["headers"]
    )
    assert resp.status_code == 400
