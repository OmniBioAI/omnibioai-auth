"""SAML SSO PR3: SP metadata endpoint. No login/ACS/SLO exists yet -- see
app/services/org_saml_service.py's module docstring.
"""

import uuid

import pytest
from lxml import etree
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import OrganizationSAMLConfig
from app.services import org_saml_service

# Same physical file conftest.py's `client` fixture uses -- a second
# connection opened directly so tests can create an OrganizationSAMLConfig
# row without going through any HTTP route (none exist yet, PR8), same
# convention as tests/test_organization_saml_config.py's _DirectSession.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_MD_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}


def _register_and_login(client, email=None):
    email = email or f"samlmeta-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _create_org(client, name="SAML Metadata Test Org"):
    owner = _register_and_login(client)
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created["owner"] = owner
    return created


@pytest.fixture
def org(client):
    return _create_org(client)


# ── HTTP layer ───────────────────────────────────────────────────────────


def test_metadata_returns_200_with_correct_content_type(client, org):
    resp = client.get(f"/auth/saml/{org['slug']}/metadata")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/samlmetadata+xml")


def test_metadata_is_well_formed_xml_and_matches_org_slug(client, org):
    resp = client.get(f"/auth/saml/{org['slug']}/metadata")
    root = etree.fromstring(resp.content)

    entity_id = root.get("entityID")
    assert org["slug"] in entity_id

    acs = root.find(".//md:AssertionConsumerService", _MD_NS)
    assert acs is not None
    assert acs.get("Location") == f"https://webstudio.omnibioai.org/auth/saml/{org['slug']}/acs"
    assert acs.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    name_id_format = root.find(".//md:NameIDFormat", _MD_NS)
    assert name_id_format.text == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


def test_metadata_works_without_any_organizationsamlconfig_row(client, org):
    """The whole point (see org_saml_service's module docstring): an org
    that has never configured SAML at all must still get valid metadata
    -- that's the document needed to *start* configuring it. No
    OrganizationSAMLConfig row is created anywhere in this test."""
    resp = client.get(f"/auth/saml/{org['slug']}/metadata")
    assert resp.status_code == 200
    root = etree.fromstring(resp.content)
    assert root.tag == "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor"


def test_metadata_unknown_org_returns_404(client):
    resp = client.get("/auth/saml/does-not-exist-org-slug-xyz/metadata")
    assert resp.status_code == 404


def test_two_different_organizations_get_different_entity_ids_and_acs_urls(client):
    org_a = _create_org(client, "SAML Meta Org A")
    org_b = _create_org(client, "SAML Meta Org B")

    root_a = etree.fromstring(client.get(f"/auth/saml/{org_a['slug']}/metadata").content)
    root_b = etree.fromstring(client.get(f"/auth/saml/{org_b['slug']}/metadata").content)

    assert root_a.get("entityID") != root_b.get("entityID")

    acs_a = root_a.find(".//md:AssertionConsumerService", _MD_NS).get("Location")
    acs_b = root_b.find(".//md:AssertionConsumerService", _MD_NS).get("Location")
    assert acs_a != acs_b


def test_metadata_contains_no_idp_configuration_data(client, org):
    """SP metadata describes this SP's own identity only -- it must never
    leak anything about the org's OrganizationSAMLConfig (issuer/sso_url/
    certificate), even if one exists, since this document is served
    publicly, unauthenticated. Confirms org_saml_service's own claim
    (module docstring: "this module never queries that table") by
    planting a config row with sentinel values and proving the response
    is unaffected."""
    session = _DirectSession()
    try:
        session.add(OrganizationSAMLConfig(
            organization_id=org["id"],
            entity_id="https://idp.example.com/SENTINEL-SHOULD-NOT-LEAK",
            sso_url="https://idp.example.com/sso/SENTINEL-SHOULD-NOT-LEAK",
            x509_certificate="SENTINEL-CERT-SHOULD-NOT-LEAK",
        ))
        session.commit()
    finally:
        session.close()

    resp = client.get(f"/auth/saml/{org['slug']}/metadata")
    assert resp.status_code == 200
    assert b"SENTINEL" not in resp.content


# ── Service layer (direct, no HTTP) ────────────────────────────────────


def test_build_sp_metadata_is_independent_of_organization_existing():
    """org_saml_service never queries the database at all -- confirmed by
    calling it directly with a slug that was never registered as a real
    Organization anywhere. The HTTP layer (routes_saml.py) is what adds
    the 404-for-unknown-org check; the service function itself has no
    such dependency, exactly as its own docstring claims."""
    metadata = org_saml_service.build_sp_metadata("never-registered-org-slug")
    assert isinstance(metadata, str)
    assert "never-registered-org-slug" in metadata
    assert "EntityDescriptor" in metadata


def test_entity_id_and_acs_url_are_pure_functions_of_org_slug():
    assert org_saml_service.entity_id_for("acme") == "https://webstudio.omnibioai.org/auth/saml/acme/metadata"
    assert org_saml_service.acs_url_for("acme") == "https://webstudio.omnibioai.org/auth/saml/acme/acs"
