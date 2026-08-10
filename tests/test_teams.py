import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import OrganizationMembership

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"team-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    resp = client.post("/auth/validate", json={"token": access_token})
    return resp.json()["user_id"]


def _invite_to_org(client, org, email):
    """Org-level invite (existing endpoint), immediately activated by a
    direct DB write. No accept-invite flow exists in this codebase yet
    (test_organization_role_assignment_api.py's
    test_assign_roles_self_escalation_blocked documents this same gap) --
    an invited membership's status stays "invited", which fails
    get_org_membership's active-status filter, so the invitee could never
    call any org- or team-scoped endpoint at all otherwise. Mirrors
    test_pr13_escalation_guards.py's own
    test_org_admin_cannot_assign_admin_role_to_another_member_via_new_surface
    -- "Activate the invite the same way an accept-flow would -- direct
    DB write, since accept-invite isn't this test's concern.\""""
    resp = client.post(f"/orgs/{org['id']}/invite", json={"email": email}, headers=org["owner_headers"])
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]
    db = _DirectSession()
    try:
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.organization_id == org["id"], OrganizationMembership.user_id == user_id)
            .first()
        )
        membership.status = "active"
        db.commit()
    finally:
        db.close()


def _invite_to_team(client, org_id, team_id, email, headers, role=None):
    body = {"email": email}
    if role is not None:
        body["role"] = role
    return client.post(f"/orgs/{org_id}/teams/{team_id}/invite", json=body, headers=headers)


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Team Test Org", "slug": f"team-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def test_create_and_list_team(client, org):
    resp = client.post(f"/orgs/{org['id']}/teams", json={"name": "Wet Lab"}, headers=org["owner_headers"])
    assert resp.status_code == 201
    assert resp.json()["name"] == "Wet Lab"
    assert resp.json()["member_user_ids"] == []

    listed = client.get(f"/orgs/{org['id']}/teams", headers=org["owner_headers"])
    assert listed.status_code == 200
    assert any(t["name"] == "Wet Lab" for t in listed.json())


def test_list_teams_requires_membership(client, org):
    outsider = _register_and_login(client)
    resp = client.get(f"/orgs/{org['id']}/teams", headers=_auth_header(outsider["access_token"]))
    assert resp.status_code == 404


def test_create_team_requires_manage_teams(client, org):
    outsider = _register_and_login(client)
    resp = client.post(
        f"/orgs/{org['id']}/teams", json={"name": "Nope"}, headers=_auth_header(outsider["access_token"])
    )
    assert resp.status_code == 404  # non-member: not even visible


def test_set_team_members_org_owner_only(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "Core"}, headers=org["owner_headers"]).json()
    owner_id = _user_id(client, org["owner"]["access_token"])

    resp = client.put(
        f"/orgs/{org['id']}/teams/{team['id']}/members",
        json={"user_ids": [owner_id]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["member_user_ids"] == [owner_id]


def test_set_team_members_rejects_non_org_member(client, org):
    """A user_id that isn't a member of this org at all must not be
    addable to one of its teams, even by a raw ID in the request body."""
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "Guarded"}, headers=org["owner_headers"]).json()
    outsider = _register_and_login(client)
    outsider_id = _user_id(client, outsider["access_token"])

    resp = client.put(
        f"/orgs/{org['id']}/teams/{team['id']}/members",
        json={"user_ids": [outsider_id]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_delete_team(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "Temp"}, headers=org["owner_headers"]).json()
    resp = client.delete(f"/orgs/{org['id']}/teams/{team['id']}", headers=org["owner_headers"])
    assert resp.status_code == 204

    listed = client.get(f"/orgs/{org['id']}/teams", headers=org["owner_headers"])
    assert not any(t["id"] == team["id"] for t in listed.json())


# ── Cross-org isolation ──────────────────────────────────────────────────────


def test_team_not_visible_via_other_org(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "Private"}, headers=org["owner_headers"]).json()

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs", json={"name": "Other Org", "slug": f"other-org-{uuid.uuid4().hex[:8]}"}, headers=other_headers
    ).json()

    # Guess org A's team_id but address it through org B's own (valid)
    # membership -- team_service.get_team filters by organization_id, so
    # this must 404, not leak org A's team.
    resp = client.delete(f"/orgs/{other_org['id']}/teams/{team['id']}", headers=other_headers)
    assert resp.status_code == 404


# ── Step 3: GET /teams/{id}, PATCH (rename+description) ─────────────────────


def test_get_team_detail(client, org):
    created = client.post(
        f"/orgs/{org['id']}/teams", json={"name": "Detail", "description": "desc"}, headers=org["owner_headers"]
    ).json()

    resp = client.get(f"/orgs/{org['id']}/teams/{created['id']}", headers=org["owner_headers"])
    assert resp.status_code == 200
    assert resp.json()["name"] == "Detail"
    assert resp.json()["description"] == "desc"


def test_get_team_detail_requires_membership(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    outsider = _register_and_login(client)
    resp = client.get(f"/orgs/{org['id']}/teams/{team['id']}", headers=_auth_header(outsider["access_token"]))
    assert resp.status_code == 404


def test_rename_team_by_org_admin(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "Old"}, headers=org["owner_headers"]).json()

    resp = client.patch(
        f"/orgs/{org['id']}/teams/{team['id']}", json={"name": "New", "description": "now described"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New"
    assert resp.json()["description"] == "now described"


def test_rename_team_partial_update_leaves_other_field_unchanged(client, org):
    team = client.post(
        f"/orgs/{org['id']}/teams", json={"name": "Keep Desc", "description": "original"}, headers=org["owner_headers"]
    ).json()

    resp = client.patch(
        f"/orgs/{org['id']}/teams/{team['id']}", json={"name": "Renamed"}, headers=org["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    assert resp.json()["description"] == "original"


def test_rename_team_forbidden_for_plain_org_member(client, org):
    """A plain org member (org_member role, no manage_teams, and not this
    team's own admin) must not be able to rename it."""
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    plain = _register_and_login(client)
    _invite_to_org(client, org, plain["email"])

    resp = client.patch(
        f"/orgs/{org['id']}/teams/{team['id']}", json={"name": "Hijacked"},
        headers=_auth_header(plain["access_token"]),
    )
    assert resp.status_code == 403


def test_rename_team_allowed_for_team_admin_without_manage_teams(client, org):
    """Decision: team admin manages members + rename, without needing the
    org-level manage_teams permission at all."""
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    team_admin = _register_and_login(client)
    _invite_to_org(client, org, team_admin["email"])
    invite_resp = _invite_to_team(client, org["id"], team["id"], team_admin["email"], org["owner_headers"], role="admin")
    assert invite_resp.status_code == 201

    resp = client.patch(
        f"/orgs/{org['id']}/teams/{team['id']}", json={"name": "Renamed By Team Admin"},
        headers=_auth_header(team_admin["access_token"]),
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed By Team Admin"


# ── Step 3: GET /teams/{id}/members, POST /invite ────────────────────────────


def test_invite_to_team_success(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    invitee = _register_and_login(client)
    _invite_to_org(client, org, invitee["email"])

    resp = _invite_to_team(client, org["id"], team["id"], invitee["email"], org["owner_headers"], role="viewer")
    assert resp.status_code == 201
    body = resp.json()
    assert body["role"] == "viewer"
    assert body["invited_by_user_id"] == _user_id(client, org["owner"]["access_token"])

    members = client.get(f"/orgs/{org['id']}/teams/{team['id']}/members", headers=org["owner_headers"]).json()
    assert any(m["user_id"] == body["user_id"] and m["role"] == "viewer" for m in members)


def test_invite_to_team_unknown_email_404(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    resp = _invite_to_team(client, org["id"], team["id"], "nobody@omnibioai.test", org["owner_headers"])
    assert resp.status_code == 404


def test_invite_to_team_rejects_non_org_member(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    outsider = _register_and_login(client)
    resp = _invite_to_team(client, org["id"], team["id"], outsider["email"], org["owner_headers"])
    assert resp.status_code == 400


def test_invite_to_team_forbidden_for_plain_member(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    plain = _register_and_login(client)
    _invite_to_org(client, org, plain["email"])
    someone_else = _register_and_login(client)
    _invite_to_org(client, org, someone_else["email"])

    resp = _invite_to_team(
        client, org["id"], team["id"], someone_else["email"], _auth_header(plain["access_token"])
    )
    assert resp.status_code == 403


# ── Step 3: PUT .../members/{uid}/role, DELETE .../members/{uid} ────────────


def test_update_team_member_role(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    invitee = _register_and_login(client)
    _invite_to_org(client, org, invitee["email"])
    invited = _invite_to_team(client, org["id"], team["id"], invitee["email"], org["owner_headers"], role="viewer").json()

    resp = client.put(
        f"/orgs/{org['id']}/teams/{team['id']}/members/{invited['user_id']}/role",
        json={"role": "admin"}, headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_update_team_member_role_blocks_demoting_last_admin(client, org):
    owner_id = _user_id(client, org["owner"]["access_token"])
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    # Owner invites themselves as the team's sole admin.
    _invite_to_team(client, org["id"], team["id"], org["owner"]["email"], org["owner_headers"], role="admin")

    resp = client.put(
        f"/orgs/{org['id']}/teams/{team['id']}/members/{owner_id}/role",
        json={"role": "member"}, headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_remove_team_member(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    invitee = _register_and_login(client)
    _invite_to_org(client, org, invitee["email"])
    invited = _invite_to_team(client, org["id"], team["id"], invitee["email"], org["owner_headers"]).json()

    resp = client.delete(
        f"/orgs/{org['id']}/teams/{team['id']}/members/{invited['user_id']}", headers=org["owner_headers"]
    )
    assert resp.status_code == 204

    members = client.get(f"/orgs/{org['id']}/teams/{team['id']}/members", headers=org["owner_headers"]).json()
    assert not any(m["user_id"] == invited["user_id"] for m in members)


def test_remove_team_member_blocks_removing_last_admin(client, org):
    owner_id = _user_id(client, org["owner"]["access_token"])
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    _invite_to_team(client, org["id"], team["id"], org["owner"]["email"], org["owner_headers"], role="admin")

    resp = client.delete(
        f"/orgs/{org['id']}/teams/{team['id']}/members/{owner_id}", headers=org["owner_headers"]
    )
    assert resp.status_code == 400


# ── Step 3: POST /teams/{id}/leave ───────────────────────────────────────────


def test_leave_team(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    leaver = _register_and_login(client)
    _invite_to_org(client, org, leaver["email"])
    _invite_to_team(client, org["id"], team["id"], leaver["email"], org["owner_headers"], role="member")

    resp = client.post(f"/orgs/{org['id']}/teams/{team['id']}/leave", headers=_auth_header(leaver["access_token"]))
    assert resp.status_code == 204

    members = client.get(f"/orgs/{org['id']}/teams/{team['id']}/members", headers=org["owner_headers"]).json()
    assert not any(m["user_id"] == _user_id(client, leaver["access_token"]) for m in members)


def test_leave_team_blocks_last_admin(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    _invite_to_team(client, org["id"], team["id"], org["owner"]["email"], org["owner_headers"], role="admin")

    resp = client.post(f"/orgs/{org['id']}/teams/{team['id']}/leave", headers=org["owner_headers"])
    assert resp.status_code == 400


def test_leave_team_not_a_member_404(client, org):
    team = client.post(f"/orgs/{org['id']}/teams", json={"name": "T"}, headers=org["owner_headers"]).json()
    non_member = _register_and_login(client)
    _invite_to_org(client, org, non_member["email"])

    resp = client.post(
        f"/orgs/{org['id']}/teams/{team['id']}/leave", headers=_auth_header(non_member["access_token"])
    )
    assert resp.status_code == 404
