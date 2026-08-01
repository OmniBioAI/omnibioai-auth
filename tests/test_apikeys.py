import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import apikey_service

# Same physical file conftest.py's `client` fixture uses (TEST_DB_URL =
# "sqlite:///./test.db") -- a second connection to it, opened directly so
# these tests can call apikey_service.verify_api_key() itself. This matters
# because no HTTP route exposes verify_api_key() yet (it's wired up in
# Phase 1 PR3), so the only way to actually prove "a revoked key fails to
# authenticate" -- as opposed to merely "its status field says revoked" --
# is to call the verification function directly.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"apikey-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "API Key Test Org", "slug": f"apikey-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def test_create_api_key_returns_full_key_once(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/api-keys",
        json={"name": "CI pipeline", "scopes": ["manage_teams"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "CI pipeline"
    assert data["scopes"] == ["manage_teams"]
    assert data["key"].startswith("omni_sk_")
    assert data["key_prefix"] == data["key"][: len(data["key_prefix"])]


def test_create_api_key_rejects_scope_caller_does_not_hold(client, org):
    """org_admin holds manage_org/manage_teams/manage_api_keys -- a scope
    outside that set must be rejected, so a key can never grant more than
    its issuer actually has."""
    resp = client.post(
        f"/orgs/{org['id']}/api-keys",
        json={"name": "Overreaching", "scopes": ["manage_org", "some_permission_nobody_has"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_list_api_keys_never_exposes_full_key_or_hash(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys",
        json={"name": "Listed key", "scopes": []},
        headers=org["owner_headers"],
    )
    full_key = create.json()["key"]

    listed = client.get(f"/orgs/{org['id']}/api-keys", headers=org["owner_headers"])
    assert listed.status_code == 200
    body = listed.json()
    assert any(k["name"] == "Listed key" for k in body)
    serialized = str(body)
    assert full_key not in serialized
    assert "key_hash" not in serialized


def test_revoke_api_key(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Revoke me", "scopes": []}, headers=org["owner_headers"]
    )
    key_id = create.json()["id"]

    resp = client.delete(f"/orgs/{org['id']}/api-keys/{key_id}", headers=org["owner_headers"])
    assert resp.status_code == 204

    listed = client.get(f"/orgs/{org['id']}/api-keys", headers=org["owner_headers"])
    revoked = next(k for k in listed.json() if k["id"] == key_id)
    assert revoked["status"] == "revoked"


def test_missing_token_rejected(client, org):
    resp = client.get(f"/orgs/{org['id']}/api-keys")
    assert resp.status_code in (401, 403)


# ── Cross-org isolation ──────────────────────────────────────────────────────


def test_non_member_cannot_list_or_revoke_api_keys(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Protected", "scopes": []}, headers=org["owner_headers"]
    )
    key_id = create.json()["id"]

    outsider = _register_and_login(client)
    outsider_headers = _auth_header(outsider["access_token"])

    listed = client.get(f"/orgs/{org['id']}/api-keys", headers=outsider_headers)
    assert listed.status_code == 404

    revoke = client.delete(f"/orgs/{org['id']}/api-keys/{key_id}", headers=outsider_headers)
    assert revoke.status_code == 404

    # Confirm the key is still active -- the rejected revoke attempt above
    # must not have had any effect.
    still_listed = client.get(f"/orgs/{org['id']}/api-keys", headers=org["owner_headers"])
    assert next(k for k in still_listed.json() if k["id"] == key_id)["status"] == "active"


def test_api_key_from_org_a_not_reachable_via_org_b(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Org A key", "scopes": []}, headers=org["owner_headers"]
    )
    key_id = create.json()["id"]

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs",
        json={"name": "Org B", "slug": f"org-b-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    ).json()

    resp = client.delete(f"/orgs/{other_org['id']}/api-keys/{key_id}", headers=other_headers)
    assert resp.status_code == 404


# ── Direct service-level checks: verify_api_key() itself ────────────────────
# Not reachable via any route yet (see module docstring above) -- these call
# the service function directly to prove the actual authentication contract,
# not just the API-visible status field.


def test_verify_api_key_accepts_active_key(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "Direct-verify", "scopes": []}, headers=org["owner_headers"]
    )
    full_key = create.json()["key"]
    key_id = create.json()["id"]

    db = _DirectSession()
    try:
        result = apikey_service.verify_api_key(db, full_key)
    finally:
        db.close()

    assert result is not None
    assert result.id == key_id


def test_verify_api_key_rejects_revoked_key(client, org):
    create = client.post(
        f"/orgs/{org['id']}/api-keys", json={"name": "To-be-revoked", "scopes": []}, headers=org["owner_headers"]
    )
    full_key = create.json()["key"]
    key_id = create.json()["id"]

    revoke = client.delete(f"/orgs/{org['id']}/api-keys/{key_id}", headers=org["owner_headers"])
    assert revoke.status_code == 204

    db = _DirectSession()
    try:
        result = apikey_service.verify_api_key(db, full_key)
    finally:
        db.close()

    assert result is None


def test_verify_api_key_rejects_unknown_key(client, org):
    db = _DirectSession()
    try:
        result = apikey_service.verify_api_key(db, "omni_sk_this_key_was_never_issued_by_anything")
    finally:
        db.close()

    assert result is None
