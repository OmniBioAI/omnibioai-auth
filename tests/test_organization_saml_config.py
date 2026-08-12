"""SAML SSO PR2: OrganizationSAMLConfig -- schema only. No CRUD API (PR8),
no SP metadata/login/ACS/SLO endpoint (PR3-PR7), and no login path reads
or writes this table yet. These tests exercise the ORM model and its
constraints directly, via a raw session, the same way tests/test_org_sso.py
covered OrganizationSSOConfig before Phase 2 PR3 added org-admin CRUD
routes on top of it -- there is no route to test here yet.
"""

import uuid

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.models import OrganizationSAMLConfig

# Same physical file conftest.py's `client` fixture uses -- a second
# connection opened directly so tests can create/query OrganizationSAMLConfig
# rows without going through any HTTP route (none exist yet), same
# convention as tests/test_org_sso.py's _DirectSession.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_VALID_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest-cert-body-not-real\n"
    "-----END CERTIFICATE-----"
)


def _register_and_login(client, email=None):
    email = email or f"samlconfig-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _create_org(client, name_prefix="SAML Config Test Org"):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": name_prefix, "slug": f"{name_prefix.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


@pytest.fixture
def org(client):
    return _create_org(client)


def _config_kwargs(org_id, **overrides):
    kwargs = {
        "organization_id": org_id,
        "entity_id": "https://idp.example.com/metadata",
        "sso_url": "https://idp.example.com/sso",
        "x509_certificate": _VALID_CERT,
    }
    kwargs.update(overrides)
    return kwargs


# ── 1. Basic creation ───────────────────────────────────────────────────


def test_organization_saml_config_can_be_created(client, org):
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"]))
        session.add(config)
        session.commit()
        session.refresh(config)

        assert config.id is not None
        assert config.organization_id == org["id"]
        assert config.entity_id == "https://idp.example.com/metadata"
        assert config.sso_url == "https://idp.example.com/sso"
        assert config.x509_certificate == _VALID_CERT
    finally:
        session.close()


# ── 2. organization_id required ─────────────────────────────────────────


def test_organization_id_is_required(client):
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(
            entity_id="https://idp.example.com/metadata",
            sso_url="https://idp.example.com/sso",
            x509_certificate=_VALID_CERT,
        )
        session.add(config)
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


# ── 3. organization_id has a real FK to organizations.id ───────────────


def test_organization_id_has_foreign_key_to_organizations():
    """Schema-level check via introspection, not a runtime-enforcement
    check -- this repo's SQLite test database never enables `PRAGMA
    foreign_keys=ON` (grep confirms it -- MySQL enforces FKs by default
    via InnoDB in every real deployment; SQLite here is deliberately left
    at its default). The migration's `sa.ForeignKey("organizations.id")`
    is what real deployments rely on; this test confirms it actually
    landed in the schema, the same thing test_migrations.py's own
    introspection-based assertions check for every other table."""
    inspector = inspect(_direct_engine)
    fks = inspector.get_foreign_keys("organization_saml_configs")
    matching = [
        fk for fk in fks
        if fk["constrained_columns"] == ["organization_id"] and fk["referred_table"] == "organizations"
    ]
    assert matching, f"no FK from organization_saml_configs.organization_id to organizations found: {fks}"


# ── 4. One org cannot have two SAML configs ─────────────────────────────


def test_one_organization_cannot_have_two_saml_configs(client, org):
    session = _DirectSession()
    try:
        session.add(OrganizationSAMLConfig(**_config_kwargs(
            org["id"], entity_id="https://idp-1.example.com/metadata", sso_url="https://idp-1.example.com/sso",
        )))
        session.commit()

        session.add(OrganizationSAMLConfig(**_config_kwargs(
            org["id"], entity_id="https://idp-2.example.com/metadata", sso_url="https://idp-2.example.com/sso",
        )))
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()


# ── 5. Two different orgs each get their own config ─────────────────────


def test_two_different_organizations_each_get_their_own_config(client):
    org_a = _create_org(client, "SAML Org A")
    org_b = _create_org(client, "SAML Org B")

    session = _DirectSession()
    try:
        session.add(OrganizationSAMLConfig(**_config_kwargs(
            org_a["id"], entity_id="https://idp-a.example.com/metadata", sso_url="https://idp-a.example.com/sso",
        )))
        session.add(OrganizationSAMLConfig(**_config_kwargs(
            org_b["id"], entity_id="https://idp-b.example.com/metadata", sso_url="https://idp-b.example.com/sso",
        )))
        session.commit()

        rows = (
            session.query(OrganizationSAMLConfig)
            .filter(OrganizationSAMLConfig.organization_id.in_([org_a["id"], org_b["id"]]))
            .all()
        )
        assert {r.organization_id for r in rows} == {org_a["id"], org_b["id"]}
    finally:
        session.close()


# ── 6. attribute_mapping accepts the expected JSON structure ────────────


def test_attribute_mapping_accepts_expected_json_structure(client, org):
    mapping = {
        "email": "NameID",
        "first_name": "givenName",
        "last_name": "sn",
        "groups": "groups",
        "department": "department",
    }
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"], attribute_mapping=mapping))
        session.add(config)
        session.commit()
        session.refresh(config)
        assert config.attribute_mapping == mapping
    finally:
        session.close()


# ── 7. enabled defaults correctly ────────────────────────────────────────


def test_enabled_defaults_to_false(client, org):
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"]))
        session.add(config)
        session.commit()
        session.refresh(config)
        assert config.enabled is False
    finally:
        session.close()


# ── 8. status defaults correctly ─────────────────────────────────────────


def test_status_defaults_to_pending_verification(client, org):
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"]))
        session.add(config)
        session.commit()
        session.refresh(config)
        assert config.status == "pending_verification"
    finally:
        session.close()


# ── 9. created_at / updated_at follow repository conventions ────────────


def test_created_at_and_updated_at_follow_repository_conventions(client, org):
    """created_at gets an ORM-level default at insert time (mirroring
    OrganizationSSOConfig.created_at); updated_at stays NULL until
    something explicitly sets it -- there is no update path yet in this
    PR, so it must still be None right after creation."""
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"]))
        session.add(config)
        session.commit()
        session.refresh(config)
        assert config.created_at is not None
        assert config.updated_at is None
    finally:
        session.close()


# ── 10. updated_by_user_id follows existing ownership convention ────────


def test_updated_by_user_id_follows_existing_ownership_convention(client, org):
    owner_id = client.post(
        "/auth/validate", json={"token": org["owner"]["access_token"]}
    ).json()["user_id"]

    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(**_config_kwargs(org["id"], updated_by_user_id=owner_id))
        session.add(config)
        session.commit()
        session.refresh(config)
        assert config.updated_by_user_id == owner_id
    finally:
        session.close()
