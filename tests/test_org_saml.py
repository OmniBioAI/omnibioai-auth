"""PR8: per-org SAML IdP registration -- admin CRUD only, over the schema
PR2 (0021_organization_saml_config) already created. No discovery/
verification network call exists for SAML (unlike tests/test_org_sso.py's
OIDC equivalent) -- see app/services/org_saml_service.py's module
docstring for why. Structurally mirrors test_org_sso.py deliberately
closely: same permission (manage_sso, reused rather than a new
manage_saml), same platform-admin/isolation/duplicate-config shape.
"""

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Same physical file conftest.py's `client` fixture uses -- a second
# connection opened directly so tests can assert on raw column values,
# same convention as tests/test_org_sso.py.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_ENTITY_ID = "https://idp.acme-test.example.com/entity"
_SSO_URL = "https://idp.acme-test.example.com/sso"
_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpTCCAQ4CAQAwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLdGVzdC1zYW1s\n"
    "LWlkcDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBYxFDASBgNVBAMM\n"
    "C3Rlc3Qtc2FtbC1pZHBUUFBURVNUQ0VSVElGSUNBVEVOT1RSRUFMS0VZTUFURVJJ\n"
    "QUxKVVNURk9SU0hBUEVWQUxJREFUSU9OT05MWU5PVFVTRURGT1JBTllTSUdOQVRV\n"
    "UkVWRVJJRklDQVRJT05JTlRIRVNFVEVTVFM=\n"
    "-----END CERTIFICATE-----"
)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"orgsaml-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    resp = client.post("/auth/validate", json={"token": access_token})
    return resp.json()["user_id"]


@pytest.fixture(scope="session")
def admin_token(client):
    import os

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
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Org SAML Test Org", "slug": f"org-saml-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _create_body(**overrides):
    body = {
        "entity_id": _ENTITY_ID,
        "sso_url": _SSO_URL,
        "x509_certificate": _CERT,
        "attribute_mapping": {"email": "NameID"},
    }
    body.update(overrides)
    return body


# ── 1. Successful CRUD ───────────────────────────────────────────────────


def test_create_saml_config_success(client, org):
    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    assert resp.status_code == 201
    data = resp.json()
    assert data["entity_id"] == _ENTITY_ID
    assert data["sso_url"] == _SSO_URL
    assert data["x509_certificate"] == _CERT
    assert data["attribute_mapping"] == {"email": "NameID"}
    assert data["status"] == "active"
    assert data["enabled"] is False  # model default, untouched by create


def test_create_persists_to_database(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    db = _DirectSession()
    try:
        row = db.execute(
            text("SELECT entity_id, sso_url, status FROM organization_saml_configs WHERE organization_id = :oid"),
            {"oid": org["id"]},
        ).fetchone()
    finally:
        db.close()

    assert row is not None
    assert row[0] == _ENTITY_ID
    assert row[1] == _SSO_URL
    assert row[2] == "active"


def test_get_returns_persisted_configuration(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    resp = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert resp.status_code == 200
    assert resp.json()["entity_id"] == _ENTITY_ID


def test_get_saml_config_404_when_none_exists(client, org):
    resp = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert resp.status_code == 404


def test_update_persists_changes(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    new_sso_url = "https://idp2.acme-test.example.com/sso"
    resp = client.patch(
        f"/orgs/{org['id']}/saml", json={"sso_url": new_sso_url}, headers=org["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["sso_url"] == new_sso_url
    # entity_id/certificate untouched by a partial update
    assert resp.json()["entity_id"] == _ENTITY_ID

    check = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert check.json()["sso_url"] == new_sso_url


def test_update_enabled_and_status(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    resp = client.patch(
        f"/orgs/{org['id']}/saml", json={"enabled": True, "status": "disabled"}, headers=org["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    assert resp.json()["status"] == "disabled"


def test_update_does_not_create_a_second_configuration(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    client.patch(f"/orgs/{org['id']}/saml", json={"sso_url": "https://new.example.com/sso"}, headers=org["owner_headers"])

    db = _DirectSession()
    try:
        count = db.execute(
            text("SELECT COUNT(*) FROM organization_saml_configs WHERE organization_id = :oid"),
            {"oid": org["id"]},
        ).scalar()
    finally:
        db.close()
    assert count == 1


def test_delete_saml_config(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    resp = client.delete(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert resp.status_code == 204

    check = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert check.status_code == 404


# ── 2. One IdP per organization ──────────────────────────────────────────


def test_second_saml_config_for_same_org_rejected(client, org):
    first = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    assert first.status_code == 201

    second = client.post(
        f"/orgs/{org['id']}/saml", json=_create_body(entity_id="https://other-idp.example.com/entity"),
        headers=org["owner_headers"],
    )
    assert second.status_code == 409

    check = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert check.json()["entity_id"] == _ENTITY_ID  # original untouched


def test_delete_then_create_allowed(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    client.delete(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])

    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    assert resp.status_code == 201


# ── 3. Validation ─────────────────────────────────────────────────────────


def test_empty_entity_id_rejected(client, org):
    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(entity_id=""), headers=org["owner_headers"])
    assert resp.status_code == 422
    assert client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"]).status_code == 404


def test_non_http_scheme_sso_url_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/saml", json=_create_body(sso_url="ftp://idp.example.com/sso"),
        headers=org["owner_headers"],
    )
    assert resp.status_code == 422
    assert client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"]).status_code == 404


def test_http_sso_url_rejected_by_default(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/saml", json=_create_body(sso_url="http://idp.example.com/sso"),
        headers=org["owner_headers"],
    )
    assert resp.status_code == 422
    assert client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"]).status_code == 404


def test_sso_url_without_hostname_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/saml", json=_create_body(sso_url="https:///no-host"),
        headers=org["owner_headers"],
    )
    assert resp.status_code == 422


def test_malformed_certificate_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/saml", json=_create_body(x509_certificate="not-a-real-certificate"),
        headers=org["owner_headers"],
    )
    assert resp.status_code == 422
    assert client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"]).status_code == 404


def test_invalid_attribute_mapping_shape_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/saml",
        json={**_create_body(), "attribute_mapping": {"email": 12345}},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 422


def test_invalid_status_value_rejected(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    resp = client.patch(
        f"/orgs/{org['id']}/saml", json={"status": "not-a-real-status"}, headers=org["owner_headers"]
    )
    assert resp.status_code == 422

    unchanged = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert unchanged.json()["status"] == "active"  # rejected update left the row untouched


def test_update_invalid_sso_url_leaves_existing_config_untouched(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    resp = client.patch(
        f"/orgs/{org['id']}/saml", json={"sso_url": "ftp://bad.example.com"}, headers=org["owner_headers"]
    )
    assert resp.status_code == 422

    unchanged = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert unchanged.json()["sso_url"] == _SSO_URL


# ── 4. Permissions ────────────────────────────────────────────────────────


def test_org_admin_with_manage_sso_can_create(client, org):
    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    assert resp.status_code == 201


def test_member_without_manage_sso_receives_403(client, org, admin_headers):
    owner_id = _user_id(client, org["owner"]["access_token"])

    narrow_role = f"org-saml-narrow-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": narrow_role, "permissions": ["manage_org"]}, headers=admin_headers)
    downgrade = client.put(
        f"/orgs/{org['id']}/members/{owner_id}/roles", json={"roles": [narrow_role]}, headers=org["owner_headers"]
    )
    assert downgrade.status_code == 200

    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    assert resp.status_code == 403


def test_missing_token_rejected(client, org):
    resp = client.get(f"/orgs/{org['id']}/saml")
    assert resp.status_code in (401, 403)


def _grant_platform_admin(email: str) -> None:
    """Same technique tests/test_orgs.py's own helper of this name uses:
    the bootstrap admin@omnibioai account (admin_headers/admin_token
    above) only holds manage_roles/manage_licenses/manage_config/
    override_sso_enforcement/manage_infra/manage_cron/manage_content --
    NOT manage_all_orgs, which lives on the separate "platform_admin"
    role (Phase 3 PR0.4). A genuine platform-admin-bypass test needs a
    user actually granted that role, not the bootstrap admin account."""
    from app.db.models import Role, User

    db = _DirectSession()
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
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return _auth_header(relogged["access_token"])


def test_platform_admin_can_manage_any_org_saml_config(client, org):
    platform_admin_headers = _platform_admin_headers(client)

    resp = client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=platform_admin_headers)
    assert resp.status_code == 201

    get_resp = client.get(f"/orgs/{org['id']}/saml", headers=platform_admin_headers)
    assert get_resp.status_code == 200

    update_resp = client.patch(
        f"/orgs/{org['id']}/saml", json={"enabled": True}, headers=platform_admin_headers
    )
    assert update_resp.status_code == 200

    delete_resp = client.delete(f"/orgs/{org['id']}/saml", headers=platform_admin_headers)
    assert delete_resp.status_code == 204


# ── 5. Organization isolation ────────────────────────────────────────────


def test_org_a_cannot_view_org_b_saml_config(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs", json={"name": "Org SAML B", "slug": f"org-saml-org-b-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    ).json()

    resp = client.get(f"/orgs/{org['id']}/saml", headers=other_headers)
    assert resp.status_code == 404

    resp2 = client.get(f"/orgs/{other_org['id']}/saml", headers=org["owner_headers"])
    assert resp2.status_code == 404  # org B has no config either, but this also proves no cross-org leak


def test_org_a_cannot_update_or_delete_org_b_saml_config(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    client.post(
        "/orgs", json={"name": "Org SAML C", "slug": f"org-saml-org-c-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    )

    update = client.patch(
        f"/orgs/{org['id']}/saml", json={"sso_url": "https://hijacked.example.com/sso"}, headers=other_headers
    )
    assert update.status_code == 404

    delete = client.delete(f"/orgs/{org['id']}/saml", headers=other_headers)
    assert delete.status_code == 404

    still_there = client.get(f"/orgs/{org['id']}/saml", headers=org["owner_headers"])
    assert still_there.json()["sso_url"] == _SSO_URL


def test_config_id_cannot_be_used_to_bypass_organization_authorization(client, org):
    """There is no bare /saml-config/{config_id} route at all -- every
    endpoint is scoped by org_id from the URL path, resolved server-side
    via get_saml_config(db, org_id), never by an independently-supplied
    config primary key. This test documents that design choice: even a
    non-member who somehow learned the config's row id has no route that
    accepts it directly."""
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])

    # The only path shape that exists is org-scoped; attempting to reach
    # org A's config from a request an outsider controls still resolves
    # via org A's own org_id, which the outsider isn't a member of.
    resp = client.get(f"/orgs/{org['id']}/saml", headers=other_headers)
    assert resp.status_code == 404


def test_organization_id_in_payload_cannot_override_server_side_scope(client, org):
    """organization_id is never a client-supplied field in any PR8
    schema (OrgSAMLConfigCreate/Update) -- injecting one in the request
    body has no effect at all; the org is always resolved from the URL
    path only."""
    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs", json={"name": "Org SAML D", "slug": f"org-saml-org-d-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    ).json()

    resp = client.post(
        f"/orgs/{org['id']}/saml",
        json={**_create_body(), "organization_id": other_org["id"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201

    db = _DirectSession()
    try:
        # Queried by org["id"] itself (organization_id is UNIQUE), not by
        # entity_id -- the literal entity_id value is shared across many
        # tests in this file/session, so filtering by it alone could
        # match a different test's leftover row in the shared test DB.
        row = db.execute(
            text("SELECT organization_id FROM organization_saml_configs WHERE organization_id = :oid"),
            {"oid": org["id"]},
        ).fetchone()
    finally:
        db.close()
    assert row is not None
    assert row[0] == org["id"]  # not other_org["id"] -- the injected field was ignored


# ── 6. SAML integration ──────────────────────────────────────────────────


def test_config_created_via_api_is_readable_by_get_saml_config(client, org):
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    from app.services import org_saml_service

    db = _DirectSession()
    try:
        config = org_saml_service.get_saml_config(db, org["id"])
    finally:
        db.close()

    assert config is not None
    assert config.entity_id == _ENTITY_ID
    assert config.sso_url == _SSO_URL
    assert config.status == "active"


def test_config_created_via_api_allows_sp_initiated_login_to_start(client, org):
    """The existing PR4 login route reads exactly what PR8's create
    endpoint persists -- a config created purely through the CRUD API,
    with no direct DB manipulation, is immediately usable by the
    existing, unmodified login path."""
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])

    org_slug = None
    db = _DirectSession()
    try:
        row = db.execute(
            text("SELECT slug FROM organizations WHERE id = :oid"), {"oid": org["id"]}
        ).fetchone()
        org_slug = row[0]
    finally:
        db.close()

    resp = client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert "RelayState=" in resp.headers["location"]


def test_disabling_status_blocks_login_start(client, org):
    """Confirms PR8's `status` field is the real, working lifecycle
    control the existing login path actually reads -- setting it to
    "disabled" makes the org's SP-initiated login 404 again, the same
    "no active config" response an org with no config at all gets."""
    client.post(f"/orgs/{org['id']}/saml", json=_create_body(), headers=org["owner_headers"])
    client.patch(f"/orgs/{org['id']}/saml", json={"status": "disabled"}, headers=org["owner_headers"])

    org_slug = None
    db = _DirectSession()
    try:
        row = db.execute(text("SELECT slug FROM organizations WHERE id = :oid"), {"oid": org["id"]}).fetchone()
        org_slug = row[0]
    finally:
        db.close()

    resp = client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)
    assert resp.status_code == 404
