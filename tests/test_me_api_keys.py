"""Self-service API keys at /me/api-keys (Studio Developer page): a member
creates keys in their session's organization with scopes limited to what
they hold, issued/displayed in the public literature:read/usage:read scope
vocabulary (literature:read by default -- translated to/from the internal
dataset.read/usage.read permission names at this HTTP boundary only, see
routes_apikeys.py's PUBLIC_SCOPE_TO_PERMISSION), lists and revokes only
their own keys, is capped at MAX_ACTIVE_KEYS_PER_USER active keys, and
cannot use an API key's own token to manage keys. Sessions without an org
or an active membership are refused.
"""
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_apikeys
from app.core.config import settings
from app.db.models import OrganizationMembership
from app.services import org_service, role_service

_engine = create_engine("sqlite:///./test.db")
_Session = sessionmaker(bind=_engine)


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def _register_login(client):
    email = f"me-keys-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": "TestPassword123!"})
    return email


def _login(client, email):
    return client.post("/auth/login", json={"email": email, "password": "TestPassword123!"}).json()["access_token"]


@pytest.fixture
def scientist(client):
    """A user who owns an org and also holds the scientist role there, logged
    in after joining so the token carries the org_id."""
    email = _register_login(client)
    first = _login(client, email)
    org = client.post("/orgs", json={"name": "Me Keys", "slug": f"me-keys-{uuid.uuid4().hex[:8]}"},
                      headers=_hdr(first)).json()
    db = _Session()
    try:
        membership = db.query(OrganizationMembership).filter(OrganizationMembership.organization_id == org["id"]).one()
        role = role_service.get_or_create_role(db, "scientist", org_service.SCIENTIST_PERMISSIONS)
        membership.roles.append(role)
        db.commit()
    finally:
        db.close()
    return {"org_id": org["id"], "headers": _hdr(_login(client, email)), "email": email}


def test_create_defaults_to_literature_read_and_lists_own_keys(client, scientist):
    resp = client.post("/me/api-keys", json={"name": "notebook"}, headers=scientist["headers"])
    assert resp.status_code == 201
    created = resp.json()
    assert created["key"].startswith("omni_sk_") and created["scopes"] == ["literature:read"]

    listed = client.get("/me/api-keys", headers=scientist["headers"]).json()
    assert [k["id"] for k in listed] == [created["id"]]
    assert listed[0]["scopes"] == ["literature:read"]
    assert "key" not in listed[0]


def test_unknown_scope_name_is_rejected(client, scientist):
    """A scope that isn't one of the public literature:read/usage:read names is rejected before it
    ever reaches the caller_permissions check -- it's not a real public scope, known or not.
    """
    resp = client.post("/me/api-keys", json={"name": "x", "scopes": ["manage_billing_nope"]},
                       headers=scientist["headers"])
    assert resp.status_code == 400


def test_scopes_cannot_exceed_held_permissions(client, scientist):
    """usage:read is a real public scope (-> usage.read), but the scientist role doesn't hold
    usage.read, so requesting it is still rejected -- a known scope name is not an automatic grant.
    """
    resp = client.post("/me/api-keys", json={"name": "x", "scopes": ["usage:read"]},
                       headers=scientist["headers"])
    assert resp.status_code == 400


def test_create_with_future_expires_at(client, scientist):
    future = (datetime.utcnow() + timedelta(days=7)).isoformat()
    resp = client.post("/me/api-keys", json={"name": "temp", "expires_at": future}, headers=scientist["headers"])
    assert resp.status_code == 201
    assert resp.json()["expires_at"] is not None


def test_create_rejects_past_expires_at(client, scientist):
    past = (datetime.utcnow() - timedelta(days=1)).isoformat()
    resp = client.post("/me/api-keys", json={"name": "temp", "expires_at": past}, headers=scientist["headers"])
    assert resp.status_code == 400


def test_create_defaults_to_live_mode(client, scientist):
    resp = client.post("/me/api-keys", json={"name": "notebook"}, headers=scientist["headers"])
    created = resp.json()
    assert created["key"].startswith("omni_sk_live_")
    assert created["test"] is False


def test_create_with_test_true_issues_a_test_key(client, scientist):
    resp = client.post("/me/api-keys", json={"name": "sandbox", "test": True}, headers=scientist["headers"])
    assert resp.status_code == 201
    created = resp.json()
    assert created["key"].startswith("omni_sk_test_")
    assert created["test"] is True

    listed = client.get("/me/api-keys", headers=scientist["headers"]).json()
    assert next(k for k in listed if k["id"] == created["id"])["test"] is True


def test_rename_own_key(client, scientist):
    created = client.post("/me/api-keys", json={"name": "old"}, headers=scientist["headers"]).json()

    resp = client.patch(f"/me/api-keys/{created['id']}", json={"name": "new"}, headers=scientist["headers"])
    assert resp.status_code == 200
    assert resp.json()["name"] == "new"

    listed = client.get("/me/api-keys", headers=scientist["headers"]).json()
    assert next(k for k in listed if k["id"] == created["id"])["name"] == "new"


def test_cannot_rename_another_members_key(client, scientist):
    other = _register_login(client)
    other_token = _login(client, other)
    other_org = client.post("/orgs", json={"name": "Other2", "slug": f"other2-{uuid.uuid4().hex[:8]}"},
                            headers=_hdr(other_token)).json()
    assert other_org["id"] != scientist["org_id"]
    key = client.post("/me/api-keys", json={"name": "mine"}, headers=scientist["headers"]).json()
    other_headers = _hdr(_login(client, other))
    resp = client.patch(f"/me/api-keys/{key['id']}", json={"name": "stolen"}, headers=other_headers)
    assert resp.status_code == 404


def test_revoke_own_key_publishes_and_is_idempotent(client, scientist):
    key = client.post("/me/api-keys", json={"name": "k"}, headers=scientist["headers"]).json()
    routes_apikeys.routes_auth._pub.publish.reset_mock()
    assert client.delete(f"/me/api-keys/{key['id']}", headers=scientist["headers"]).status_code == 204
    assert routes_apikeys.routes_auth._pub.publish.call_count == 1
    assert client.delete(f"/me/api-keys/{key['id']}", headers=scientist["headers"]).status_code == 204
    assert routes_apikeys.routes_auth._pub.publish.call_count == 1
    status = {k["id"]: k["status"] for k in client.get("/me/api-keys", headers=scientist["headers"]).json()}
    assert status[key["id"]] == "revoked"


def test_cannot_see_or_revoke_another_members_key(client, scientist):
    other = _register_login(client)
    other_token = _login(client, other)
    other_org = client.post("/orgs", json={"name": "Other", "slug": f"other-{uuid.uuid4().hex[:8]}"},
                            headers=_hdr(other_token)).json()
    assert other_org["id"] != scientist["org_id"]
    key = client.post("/me/api-keys", json={"name": "mine"}, headers=scientist["headers"]).json()
    other_headers = _hdr(_login(client, other))
    assert client.get("/me/api-keys", headers=other_headers).json() == []
    assert client.delete(f"/me/api-keys/{key['id']}", headers=other_headers).status_code == 404


def test_active_key_cap(client, scientist, monkeypatch):
    monkeypatch.setattr(routes_apikeys, "MAX_ACTIVE_KEYS_PER_USER", 2)
    for i in range(2):
        assert client.post("/me/api-keys", json={"name": f"k{i}"}, headers=scientist["headers"]).status_code == 201
    assert client.post("/me/api-keys", json={"name": "k3"}, headers=scientist["headers"]).status_code == 409


def test_api_key_token_cannot_manage_keys(client, scientist, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY_EXCHANGE_SECRET", "s")
    key = client.post("/me/api-keys", json={"name": "k"}, headers=scientist["headers"]).json()["key"]
    minted = client.post("/auth/api-keys/exchange", json={"api_key": key},
                         headers={"X-Api-Key-Exchange-Secret": "s"}).json()["access_token"]
    assert client.get("/me/api-keys", headers=_hdr(minted)).status_code == 403


def test_session_without_org_is_refused(client):
    token = _login(client, _register_login(client))
    resp = client.get("/me/api-keys", headers=_hdr(token))
    assert resp.status_code in (400, 403)


def test_inactive_membership_is_refused(client, scientist):
    db = _Session()
    try:
        db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == scientist["org_id"]
        ).update({"status": "invited"})
        db.commit()
    finally:
        db.close()
    assert client.get("/me/api-keys", headers=scientist["headers"]).status_code == 403


def test_requires_authentication(client):
    assert client.get("/me/api-keys").status_code in (401, 403)
