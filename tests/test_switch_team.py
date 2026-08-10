"""Multi-user Workspaces (Studio v0.8.0), Mode B, Phase 0a: the team_id/
team_role JWT claims (auth_service.build_user_claims/resolve_team_claim)
and the POST /auth/switch-team endpoint that reissues a token with a new
one. Mirrors tests/test_jwt_org_context.py's conventions (decode the
token directly for claims not exposed on any response body) and
tests/test_teams.py's org/team HTTP fixtures.
"""

import uuid

import pytest

from app.core.jwt import decode_token


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"switch-team-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {
        "email": email,
        "password": password,
        "access_token": login.json()["access_token"],
        "refresh_token": login.json()["refresh_token"],
    }


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Switch Team Org", "slug": f"switch-team-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


@pytest.fixture
def team(client, org):
    """The org owner, also made a member of their own team (create_team
    does not add the creator as a member automatically -- routes_teams.py
    has no such behavior), so switch-team has a real membership to
    exercise."""
    created = client.post(f"/orgs/{org['id']}/teams", json={"name": "Wet Lab"}, headers=org["owner_headers"]).json()
    resp = client.post(
        f"/orgs/{org['id']}/teams/{created['id']}/invite",
        json={"email": org["owner"]["email"], "role": "admin"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201, resp.text
    return created


def _relogin(client, creds):
    """A fresh login token, issued after org/team fixtures exist -- same
    pattern test_jwt_org_context.py uses, since the token from the
    `org`/`team` fixtures' own registration predates the org/membership."""
    relogin = client.post("/auth/login", json={"email": creds["email"], "password": creds["password"]})
    body = relogin.json()
    return body["access_token"], body["refresh_token"]


# ── fresh login: personal workspace by default ──────────────────────────────


def test_fresh_login_token_has_no_team_claim(client):
    user = _register_and_login(client)
    decoded = decode_token(user["access_token"])

    assert decoded["team_id"] is None
    assert decoded["team_role"] is None


# ── POST /auth/switch-team: happy path ──────────────────────────────────────


def test_switch_team_sets_team_id_and_role_claims(client, org, team):
    access, refresh = _relogin(client, org["owner"])

    resp = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": refresh})
    assert resp.status_code == 200, resp.text
    body = resp.json()

    decoded = decode_token(body["access_token"])
    assert decoded["team_id"] == team["id"]
    assert decoded["team_role"] == "admin"
    # org_id/org_role are unaffected by a team switch.
    assert decoded["org_id"] == org["id"]


def test_switch_team_issues_a_new_refresh_token(client, org, team):
    access, refresh = _relogin(client, org["owner"])

    resp = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": refresh})
    assert resp.status_code == 200

    # The presented refresh token is single-use, same as /auth/refresh --
    # a second use must fail.
    replay = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": refresh})
    assert replay.status_code == 401


def test_switch_team_back_to_personal_workspace(client, org, team):
    _, refresh = _relogin(client, org["owner"])
    switched = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": refresh}).json()

    back = client.post(
        "/auth/switch-team", json={"team_id": None, "refresh_token": switched["refresh_token"]},
    )
    assert back.status_code == 200
    decoded = decode_token(back.json()["access_token"])
    assert decoded["team_id"] is None
    assert decoded["team_role"] is None


# ── POST /auth/switch-team: rejections ──────────────────────────────────────


def test_switch_team_rejects_unknown_team(client, org):
    _, refresh = _relogin(client, org["owner"])

    resp = client.post("/auth/switch-team", json={"team_id": 999999, "refresh_token": refresh})
    assert resp.status_code == 404


def test_switch_team_rejects_team_from_another_org(client, org, team):
    other_org_owner = _register_and_login(client)
    other_org = client.post(
        "/orgs",
        json={"name": "Other Org", "slug": f"switch-team-other-{uuid.uuid4().hex[:8]}"},
        headers=_auth_header(other_org_owner["access_token"]),
    ).json()
    _, other_refresh = _relogin(client, other_org_owner)

    # other_org's owner tries to switch into org's team.
    resp = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": other_refresh})
    assert resp.status_code == 403


def test_switch_team_rejects_non_member_of_team(client, org, team):
    """Org member, but never invited to this specific team."""
    outsider = _register_and_login(client)
    invite = client.post(f"/orgs/{org['id']}/invite", json={"email": outsider["email"]}, headers=org["owner_headers"])
    assert invite.status_code == 201

    # Activate the invite -- same direct-DB-write pattern test_teams.py's
    # _invite_to_org helper uses; no accept-invite flow exists yet.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.models import OrganizationMembership

    engine = create_engine("sqlite:///./test.db")
    db = sessionmaker(bind=engine)()
    try:
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.organization_id == org["id"], OrganizationMembership.user_id == invite.json()["user_id"])
            .first()
        )
        membership.status = "active"
        db.commit()
    finally:
        db.close()

    _, outsider_refresh = _relogin(client, outsider)
    resp = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": outsider_refresh})
    assert resp.status_code == 403


def test_switch_team_requires_a_token(client):
    resp = client.post("/auth/switch-team", json={"team_id": 1})
    assert resp.status_code == 401


# ── carry-forward across a plain /auth/refresh ──────────────────────────────


def test_refresh_preserves_active_team_after_switch(client, org, team):
    """Once switched, the selected team must survive an ordinary
    /auth/refresh -- not just switch-team itself -- since refresh is what
    the client calls on every normal token expiry."""
    _, refresh = _relogin(client, org["owner"])
    switched = client.post("/auth/switch-team", json={"team_id": team["id"], "refresh_token": refresh}).json()

    refreshed = client.post("/auth/refresh", json={"refresh_token": switched["refresh_token"]})
    assert refreshed.status_code == 200
    decoded = decode_token(refreshed.json()["access_token"])
    assert decoded["team_id"] == team["id"]
    assert decoded["team_role"] == "admin"


def test_refresh_before_any_switch_keeps_personal_workspace(client, org):
    """The common case -- a user who never switched teams -- must keep
    getting team_id=None across every refresh, not silently pick up some
    default."""
    _, refresh = _relogin(client, org["owner"])

    refreshed = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert refreshed.status_code == 200
    decoded = decode_token(refreshed.json()["access_token"])
    assert decoded["team_id"] is None
