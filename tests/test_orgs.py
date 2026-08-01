import os
import uuid

import pytest


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"org-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    resp = client.post("/auth/validate", json={"token": access_token})
    return resp.json()["user_id"]


def _unique_slug(prefix="org"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


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
def org_owner(client):
    return _register_and_login(client)


@pytest.fixture
def org_owner_headers(org_owner):
    return _auth_header(org_owner["access_token"])


# ── Org creation / membership ───────────────────────────────────────────────


def test_create_org_creator_becomes_admin_member(client, org_owner_headers):
    slug = _unique_slug()
    resp = client.post("/orgs", json={"name": "Acme Genomics", "slug": slug}, headers=org_owner_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["slug"] == slug
    assert data["name"] == "Acme Genomics"
    assert data["status"] == "active"

    members = client.get(f"/orgs/{data['id']}/members", headers=org_owner_headers)
    assert members.status_code == 200
    assert len(members.json()) == 1
    assert members.json()[0]["roles"] == ["org_admin"]
    assert members.json()[0]["status"] == "active"


def test_create_org_duplicate_slug_returns_409(client, org_owner_headers):
    slug = _unique_slug()
    client.post("/orgs", json={"name": "First", "slug": slug}, headers=org_owner_headers)
    resp = client.post("/orgs", json={"name": "Second", "slug": slug}, headers=org_owner_headers)
    assert resp.status_code == 409


def test_list_my_orgs_only_shows_my_orgs(client, org_owner_headers):
    slug = _unique_slug()
    client.post("/orgs", json={"name": "Mine", "slug": slug}, headers=org_owner_headers)
    resp = client.get("/orgs", headers=org_owner_headers)
    assert resp.status_code == 200
    assert any(o["slug"] == slug for o in resp.json())


def test_missing_token_rejected(client):
    resp = client.get("/orgs")
    assert resp.status_code in (401, 403)


def test_update_org(client, org_owner_headers):
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Original", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    resp = client.patch(f"/orgs/{org_id}", json={"name": "Renamed"}, headers=org_owner_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    # A name-only update must never touch status-tracking fields (Phase 3
    # PR2) -- no status change happened, so nothing about it is recorded.
    assert resp.json()["status_changed_at"] is None
    assert resp.json()["status_changed_reason"] is None
    assert resp.json()["status_changed_by_user_id"] is None


# ── Phase 3 PR2: platform-admin-only status changes ─────────────────────────


def _grant_platform_admin(email: str) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models import Role, User

    engine = create_engine("sqlite:///./test.db")
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin_headers(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post(
        "/auth/login", json={"email": admin["email"], "password": admin["password"]}
    ).json()
    return _auth_header(relogged["access_token"])


def test_platform_admin_can_suspend_and_reactivate_org(client, org_owner_headers):
    admin_headers = _platform_admin_headers(client)
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Suspend Me", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    suspend = client.patch(
        f"/orgs/{org_id}",
        json={"status": "suspended", "status_reason": "ToS violation"},
        headers=admin_headers,
    )
    assert suspend.status_code == 200
    body = suspend.json()
    assert body["status"] == "suspended"
    assert body["status_changed_reason"] == "ToS violation"
    assert body["status_changed_at"] is not None
    assert body["status_changed_by_user_id"] is not None

    # Reversible: reactivating fully undoes it.
    reactivate = client.patch(
        f"/orgs/{org_id}", json={"status": "active", "status_reason": "Resolved"}, headers=admin_headers
    )
    assert reactivate.status_code == 200
    assert reactivate.json()["status"] == "active"
    assert reactivate.json()["status_changed_reason"] == "Resolved"


def test_org_admin_cannot_change_own_org_status(client, org_owner_headers):
    """A real org_admin holds manage_org over their own org -- that must
    keep meaning "can rename," not "can suspend." Only manage_all_orgs
    (platform_admin) may change status."""
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Self Suspend Attempt", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    resp = client.patch(f"/orgs/{org_id}", json={"status": "suspended"}, headers=org_owner_headers)
    assert resp.status_code == 403

    unchanged = client.get(f"/orgs/{org_id}", headers=org_owner_headers)
    assert unchanged.json()["status"] == "active"


def test_invalid_status_value_rejected(client, org_owner_headers):
    admin_headers = _platform_admin_headers(client)
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Bad Status", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    resp = client.patch(f"/orgs/{org_id}", json={"status": "deleted"}, headers=admin_headers)
    assert resp.status_code == 400

    unchanged = client.get(f"/orgs/{org_id}", headers=org_owner_headers)
    assert unchanged.json()["status"] == "active"


def test_platform_admin_can_still_rename_while_changing_status(client, org_owner_headers):
    admin_headers = _platform_admin_headers(client)
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Combined Update", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    resp = client.patch(
        f"/orgs/{org_id}", json={"name": "Renamed By Admin", "status": "suspended"}, headers=admin_headers
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed By Admin"
    assert resp.json()["status"] == "suspended"


def test_invite_unknown_email_returns_404(client, org_owner_headers):
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Inviter", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    resp = client.post(
        f"/orgs/{org_id}/invite",
        json={"email": f"nobody-{uuid.uuid4().hex[:8]}@omnibioai.test"},
        headers=org_owner_headers,
    )
    assert resp.status_code == 404


def test_invite_existing_user_adds_membership(client, org_owner_headers):
    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Inviter Org", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]

    invitee = _register_and_login(client)

    resp = client.post(
        f"/orgs/{org_id}/invite", json={"email": invitee["email"]}, headers=org_owner_headers
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "invited"
    assert resp.json()["roles"] == ["org_member"]

    members = client.get(f"/orgs/{org_id}/members", headers=org_owner_headers)
    assert len(members.json()) == 2


# ── Self-escalation guard (org-scoped role assignment) ──────────────────────


def test_self_escalation_blocked_on_org_roles(client, admin_headers, org_owner_headers, org_owner):
    """A manage_org holder cannot grant themselves an org role that carries
    permissions they don't already have -- mirrors routes_roles.py's global
    self-escalation guard, applied to the new org-scoped assignment path."""
    narrow_role = f"org-narrow-{uuid.uuid4().hex[:8]}"
    client.post(
        "/roles", json={"name": narrow_role, "permissions": ["manage_org"]}, headers=admin_headers
    )
    wide_role = f"org-wide-{uuid.uuid4().hex[:8]}"
    client.post(
        "/roles",
        json={"name": wide_role, "permissions": ["manage_org", "manage_api_keys"]},
        headers=admin_headers,
    )

    slug = _unique_slug()
    create = client.post("/orgs", json={"name": "Escalation Org", "slug": slug}, headers=org_owner_headers)
    org_id = create.json()["id"]
    owner_id = _user_id(client, org_owner["access_token"])

    # Downgrade the owner from org_admin to the narrower custom role first,
    # so there's an actual gap between "roles held" and "roles being
    # requested" for the escalation guard to catch.
    narrow = client.put(
        f"/orgs/{org_id}/members/{owner_id}/roles",
        json={"roles": [narrow_role]},
        headers=org_owner_headers,
    )
    assert narrow.status_code == 200

    # Now try to grant themselves the wider role -- must be blocked, even
    # though they still hold manage_org (the permission gating this route).
    resp = client.put(
        f"/orgs/{org_id}/members/{owner_id}/roles",
        json={"roles": [wide_role]},
        headers=org_owner_headers,
    )
    assert resp.status_code == 403

    check = client.get(f"/orgs/{org_id}/members", headers=admin_headers)
    # admin isn't a member of this org, so this 404s -- verify via the
    # narrow-role holder's own token instead, which still has manage_org.
    assert check.status_code == 404
    verify = client.put(
        f"/orgs/{org_id}/members/{owner_id}/roles",
        json={"roles": [narrow_role]},  # no-op re-assert, confirms still narrow
        headers=org_owner_headers,
    )
    assert verify.status_code == 200
    assert verify.json()["roles"] == [narrow_role]


# ── Cross-org isolation ──────────────────────────────────────────────────────


@pytest.fixture
def two_orgs(client):
    """Two distinct orgs, each with its own distinct owner -- neither owner
    is a member of the other's org."""
    owner_a = _register_and_login(client)
    owner_b = _register_and_login(client)

    org_a = client.post(
        "/orgs",
        json={"name": "Org A", "slug": _unique_slug("org-a")},
        headers=_auth_header(owner_a["access_token"]),
    ).json()
    org_b = client.post(
        "/orgs",
        json={"name": "Org B", "slug": _unique_slug("org-b")},
        headers=_auth_header(owner_b["access_token"]),
    ).json()

    return {
        "org_a": org_a,
        "org_b": org_b,
        "owner_a_headers": _auth_header(owner_a["access_token"]),
        "owner_b_headers": _auth_header(owner_b["access_token"]),
    }


def test_non_member_cannot_view_org(client, two_orgs):
    resp = client.get(f"/orgs/{two_orgs['org_b']['id']}", headers=two_orgs["owner_a_headers"])
    assert resp.status_code == 404  # not 403 -- doesn't confirm existence to non-members


def test_non_member_cannot_update_org(client, two_orgs):
    resp = client.patch(
        f"/orgs/{two_orgs['org_b']['id']}",
        json={"name": "Hijacked"},
        headers=two_orgs["owner_a_headers"],
    )
    assert resp.status_code == 404

    unaffected = client.get(f"/orgs/{two_orgs['org_b']['id']}", headers=two_orgs["owner_b_headers"])
    assert unaffected.json()["name"] == "Org B"


def test_non_member_cannot_list_members(client, two_orgs):
    resp = client.get(f"/orgs/{two_orgs['org_b']['id']}/members", headers=two_orgs["owner_a_headers"])
    assert resp.status_code == 404


def test_non_member_cannot_invite(client, two_orgs):
    resp = client.post(
        f"/orgs/{two_orgs['org_b']['id']}/invite",
        json={"email": "someone@omnibioai.test"},
        headers=two_orgs["owner_a_headers"],
    )
    assert resp.status_code == 404


def test_non_member_cannot_modify_roles(client, two_orgs):
    members = client.get(f"/orgs/{two_orgs['org_b']['id']}/members", headers=two_orgs["owner_b_headers"])
    target_user_id = members.json()[0]["user_id"]

    resp = client.put(
        f"/orgs/{two_orgs['org_b']['id']}/members/{target_user_id}/roles",
        json={"roles": ["org_member"]},
        headers=two_orgs["owner_a_headers"],
    )
    assert resp.status_code == 404
