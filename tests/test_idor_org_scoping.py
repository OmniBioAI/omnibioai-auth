"""Phase 3 PR0.3: IDOR regression-test lock-in.

`~/phase3_security_review.md` flagged "a team_id/key_id/client_id valid
for a different org accepted under the URL's org_id" as a required check
before any platform-admin cross-tenant bypass (PR0.4) ships. Auditing
app/services/team_service.py, apikey_service.py, and
oauth_client_service.py directly (not assumed) shows every `get_*` lookup
already queries `WHERE organization_id = :org_id AND id = :resource_id` in
a single filter, not a resource-only lookup followed by a separate
ownership check -- so these tests exist to lock in behavior that is
already correct, proving it stays that way, not to fix a bug.

Distinct from tests/test_teams.py's existing
`test_list_teams_requires_membership` (a total outsider with no org at
all): every test here uses a caller who *is* a legitimate org_admin --
just of a different organization than the one the resource belongs to.
That's the actual IDOR shape: not "do you have access to anything," but
"does a real, valid credential for Org B let you reach Org A's resource
via Org B's URL."
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"idor-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _make_org(client, name):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


@pytest.fixture
def two_orgs(client):
    """Two independently-owned orgs. org_b's owner is a real, legitimate
    org_admin -- just not of org_a -- which is the actual caller identity
    every test below uses to probe org_a's resources."""
    return {
        "a": _make_org(client, "IDOR Org A"),
        "b": _make_org(client, "IDOR Org B"),
    }


# ── Teams ────────────────────────────────────────────────────────────────────


def test_team_in_org_a_not_reachable_via_org_b_url_for_member_update(client, two_orgs):
    org_a, org_b = two_orgs["a"], two_orgs["b"]
    team = client.post(
        f"/orgs/{org_a['id']}/teams", json={"name": "Wet Lab"}, headers=org_a["owner_headers"]
    ).json()

    resp = client.put(
        f"/orgs/{org_b['id']}/teams/{team['id']}/members",
        json={"user_ids": []},
        headers=org_b["owner_headers"],
    )
    assert resp.status_code == 404

    # Unaffected: still listed, unchanged, under org_a's own URL.
    listed = client.get(f"/orgs/{org_a['id']}/teams", headers=org_a["owner_headers"]).json()
    assert any(t["id"] == team["id"] and t["name"] == "Wet Lab" for t in listed)


def test_team_in_org_a_not_deletable_via_org_b_url(client, two_orgs):
    org_a, org_b = two_orgs["a"], two_orgs["b"]
    team = client.post(
        f"/orgs/{org_a['id']}/teams", json={"name": "Dry Lab"}, headers=org_a["owner_headers"]
    ).json()

    resp = client.delete(
        f"/orgs/{org_b['id']}/teams/{team['id']}", headers=org_b["owner_headers"]
    )
    assert resp.status_code == 404

    listed = client.get(f"/orgs/{org_a['id']}/teams", headers=org_a["owner_headers"]).json()
    assert any(t["id"] == team["id"] for t in listed)


# ── API keys ─────────────────────────────────────────────────────────────────


def test_api_key_in_org_a_not_revocable_via_org_b_url(client, two_orgs):
    org_a, org_b = two_orgs["a"], two_orgs["b"]
    key = client.post(
        f"/orgs/{org_a['id']}/api-keys",
        json={"name": "Org A CI key", "scopes": []},
        headers=org_a["owner_headers"],
    ).json()

    resp = client.delete(
        f"/orgs/{org_b['id']}/api-keys/{key['id']}", headers=org_b["owner_headers"]
    )
    assert resp.status_code == 404

    # Unaffected: still listed as active under org_a's own URL.
    listed = client.get(f"/orgs/{org_a['id']}/api-keys", headers=org_a["owner_headers"]).json()
    matching = next(k for k in listed if k["id"] == key["id"])
    assert matching["status"] == "active"


# ── OAuth clients ────────────────────────────────────────────────────────────


def test_oauth_client_in_org_a_not_revocable_via_org_b_url(client, two_orgs):
    org_a, org_b = two_orgs["a"], two_orgs["b"]
    oauth_client = client.post(
        f"/orgs/{org_a['id']}/oauth-clients",
        json={"name": "Org A integration", "scopes": []},
        headers=org_a["owner_headers"],
    ).json()

    resp = client.delete(
        f"/orgs/{org_b['id']}/oauth-clients/{oauth_client['id']}",
        headers=org_b["owner_headers"],
    )
    assert resp.status_code == 404

    listed = client.get(
        f"/orgs/{org_a['id']}/oauth-clients", headers=org_a["owner_headers"]
    ).json()
    matching = next(c for c in listed if c["id"] == oauth_client["id"])
    assert matching["status"] == "active"


# ── Service-layer lock-in (unit level, no HTTP) ─────────────────────────────
#
# Direct evidence that the query itself is scoped, not just that the route
# happens to reject the request for some other reason (e.g. a permission
# check that fires before the lookup would even run).


def test_team_service_get_team_scoped_query_rejects_cross_org_id(client, two_orgs):
    from app.services import team_service

    org_a, org_b = two_orgs["a"], two_orgs["b"]
    team = client.post(
        f"/orgs/{org_a['id']}/teams", json={"name": "Scoped Query Team"}, headers=org_a["owner_headers"]
    ).json()

    db = _DirectSession()
    try:
        assert team_service.get_team(db, org_a["id"], team["id"]) is not None
        assert team_service.get_team(db, org_b["id"], team["id"]) is None
    finally:
        db.close()


def test_apikey_service_get_api_key_scoped_query_rejects_cross_org_id(client, two_orgs):
    from app.services import apikey_service

    org_a, org_b = two_orgs["a"], two_orgs["b"]
    key = client.post(
        f"/orgs/{org_a['id']}/api-keys", json={"name": "Scoped Query Key", "scopes": []},
        headers=org_a["owner_headers"],
    ).json()

    db = _DirectSession()
    try:
        assert apikey_service.get_api_key(db, org_a["id"], key["id"]) is not None
        assert apikey_service.get_api_key(db, org_b["id"], key["id"]) is None
    finally:
        db.close()


def test_oauth_client_service_get_oauth_client_scoped_query_rejects_cross_org_id(client, two_orgs):
    from app.services import oauth_client_service

    org_a, org_b = two_orgs["a"], two_orgs["b"]
    oauth_client = client.post(
        f"/orgs/{org_a['id']}/oauth-clients", json={"name": "Scoped Query Client", "scopes": []},
        headers=org_a["owner_headers"],
    ).json()

    db = _DirectSession()
    try:
        assert oauth_client_service.get_oauth_client(db, org_a["id"], oauth_client["id"]) is not None
        assert oauth_client_service.get_oauth_client(db, org_b["id"], oauth_client["id"]) is None
    finally:
        db.close()
