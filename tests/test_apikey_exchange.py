"""POST /auth/api-keys/exchange: the gateway trades an omni_sk_ key for a
short-lived access token. Covers the shared-secret gate (disabled, wrong,
right), uniform 401s for unknown/malformed/revoked keys, the minted token's
claims and scope narrowing to the issuer's current permissions, rejection
once the issuer is suspended or leaves the org, the throttled last_used_at
write, and the invalidation message published on revoke.
"""
import json
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import routes_auth
from app.core.config import settings
from app.core.jwt import decode_token
from app.db.models import ApiKey, OrganizationMembership, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

SECRET = "test-exchange-secret"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client):
    email = f"exchange-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "access_token": login.json()["access_token"]}


@pytest.fixture
def exchange_secret(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY_EXCHANGE_SECRET", SECRET)
    return SECRET


@pytest.fixture
def org_key(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "Exchange Org", "slug": f"exchange-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{org['id']}/api-keys",
        json={"name": "literature", "scopes": ["manage_teams", "manage_api_keys"]},
        headers=headers,
    ).json()
    return {"org_id": org["id"], "headers": headers, "key": created["key"], "key_id": created["id"]}


def _exchange(client, key, secret=SECRET):
    return client.post(
        "/auth/api-keys/exchange",
        json={"api_key": key},
        headers={"X-Api-Key-Exchange-Secret": secret},
    )


def test_exchange_disabled_without_configured_secret(client, org_key, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY_EXCHANGE_SECRET", "")
    assert _exchange(client, org_key["key"], secret="").status_code == 503


def test_exchange_rejects_wrong_or_missing_secret(client, org_key, exchange_secret):
    assert _exchange(client, org_key["key"], secret="nope").status_code == 403
    resp = client.post("/auth/api-keys/exchange", json={"api_key": org_key["key"]})
    assert resp.status_code == 403


@pytest.mark.parametrize("bad_key", ["", "not-a-key", "omni_sk_" + "x" * 40, "Bearer omni_sk_abc"])
def test_exchange_rejects_unknown_or_malformed_keys_uniformly(client, exchange_secret, bad_key):
    resp = _exchange(client, bad_key)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid API key"


def test_exchange_mints_short_lived_org_scoped_token(client, org_key, exchange_secret):
    resp = _exchange(client, org_key["key"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["expires_in"] == settings.API_KEY_TOKEN_EXPIRE_MINUTES * 60
    assert data["api_key_id"] == org_key["key_id"]
    assert data["organization_id"] == org_key["org_id"]
    assert data["permissions"] == ["manage_api_keys", "manage_teams"]

    claims = decode_token(data["access_token"])
    assert claims["auth_method"] == "api_key"
    assert claims["api_key_id"] == org_key["key_id"]
    assert claims["org_id"] == org_key["org_id"]
    assert claims["roles"] == []
    assert claims["permissions"] == ["manage_api_keys", "manage_teams"]
    assert claims["type"] == "access" and claims["jti"]

    validated = client.post("/auth/validate", json={"token": data["access_token"]}).json()
    assert validated["valid"] is True
    assert validated["auth_method"] == "api_key"
    assert validated["org_id"] == org_key["org_id"]


def test_exchange_rejects_revoked_key_and_publishes_invalidation(client, org_key, exchange_secret):
    routes_auth._pub.publish.reset_mock()
    resp = client.delete(f"/orgs/{org_key['org_id']}/api-keys/{org_key['key_id']}", headers=org_key["headers"])
    assert resp.status_code == 204

    db = _DirectSession()
    try:
        key_hash = db.query(ApiKey).filter(ApiKey.id == org_key["key_id"]).one().key_hash
    finally:
        db.close()
    channel, message = routes_auth._pub.publish.call_args.args
    assert channel == "policy:invalidate"
    assert json.loads(message) == {"api_key_hash": key_hash}
    assert org_key["key"] not in message

    assert _exchange(client, org_key["key"]).status_code == 401


def test_exchange_narrows_permissions_to_issuers_current_roles(client, org_key, exchange_secret):
    db = _DirectSession()
    try:
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.organization_id == org_key["org_id"])
            .one()
        )
        membership.roles = []
        db.commit()
    finally:
        db.close()

    data = _exchange(client, org_key["key"]).json()
    assert data["permissions"] == []


def test_exchange_rejects_key_once_issuer_leaves_org(client, org_key, exchange_secret):
    db = _DirectSession()
    try:
        db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org_key["org_id"]
        ).update({"status": "invited"})
        db.commit()
    finally:
        db.close()
    assert _exchange(client, org_key["key"]).status_code == 401


def test_exchange_rejects_key_of_suspended_issuer(client, org_key, exchange_secret):
    db = _DirectSession()
    try:
        key = db.query(ApiKey).filter(ApiKey.id == org_key["key_id"]).one()
        db.query(User).filter(User.id == key.created_by_user_id).update({"status": "suspended"})
        db.commit()
    finally:
        db.close()
    assert _exchange(client, org_key["key"]).status_code == 401


def test_exchange_throttles_last_used_writes(client, org_key, exchange_secret):
    def last_used():
        db = _DirectSession()
        try:
            return db.query(ApiKey).filter(ApiKey.id == org_key["key_id"]).one().last_used_at
        finally:
            db.close()

    assert last_used() is None
    assert _exchange(client, org_key["key"]).status_code == 200
    first = last_used()
    assert first is not None
    assert _exchange(client, org_key["key"]).status_code == 200
    assert last_used() == first
