import uuid

import pytest


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
