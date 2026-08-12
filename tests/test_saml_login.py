"""SAML SSO PR4: SP-initiated login (GET /auth/saml/{org_slug}/login).
Builds on PR2 (OrganizationSAMLConfig) and PR3 (SP metadata, XML
escaping). Does NOT touch, and must not change the behavior of, ACS
(not implemented -- PR5), identity linking/JIT provisioning (PR6/PR7),
CRUD (PR8), or the existing OIDC SSO / OAuth / MFA flows -- see
tests/test_sso_login.py, still run unmodified as part of the full suite.
"""

import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import OrganizationSAMLConfig

# Same physical file conftest.py's `client` fixture uses -- a second
# connection opened directly so tests can create an OrganizationSAMLConfig
# row without going through any HTTP route (none exist yet, PR8), same
# convention as tests/test_saml_metadata.py and
# tests/test_organization_saml_config.py.
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_AUTHN_REQUEST_NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-login-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _create_org(client, name="SAML Login Test Org"):
    owner = _register_and_login(client)
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created["owner"] = owner
    return created


def _plant_saml_config(org_id, sso_url="https://idp.example.com/sso", entity_id="https://idp.example.com/entity",
                        x509_certificate="SENTINEL-CERT-SHOULD-NOT-LEAK", status="active"):
    """Direct-session insert, mirroring test_saml_metadata.py's sentinel-
    config test -- no CRUD API exists yet (PR8) to do this via HTTP."""
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(
            organization_id=org_id,
            entity_id=entity_id,
            sso_url=sso_url,
            x509_certificate=x509_certificate,
            status=status,
        )
        session.add(config)
        session.commit()
        session.refresh(config)
        return config.id
    finally:
        session.close()


@pytest.fixture
def org_with_active_saml(client):
    org = _create_org(client)
    config_id = _plant_saml_config(org["id"])
    return {"org_id": org["id"], "org_slug": org["slug"], "config_id": config_id}


def _do_login_redirect(client, org_slug):
    return client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)


def _decode_authn_request(location: str) -> etree._Element:
    query = parse_qs(urlparse(location).query)
    saml_request_deflated_b64 = query["SAMLRequest"][0]
    xml_bytes = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request_deflated_b64)
    return etree.fromstring(xml_bytes)


# ── 1. Organization / config resolution ─────────────────────────────────


def test_login_unknown_org_returns_404(client):
    resp = _do_login_redirect(client, "does-not-exist-org-slug-xyz")
    assert resp.status_code == 404


def test_login_org_without_saml_config_returns_404(client):
    org = _create_org(client, "No SAML Config Org")
    resp = _do_login_redirect(client, org["slug"])
    assert resp.status_code == 404


@pytest.mark.parametrize("status", ["pending_verification", "disabled"])
def test_login_inactive_saml_config_returns_404(client, status):
    org = _create_org(client, f"Inactive SAML {status} Org")
    _plant_saml_config(org["id"], status=status)
    resp = _do_login_redirect(client, org["slug"])
    assert resp.status_code == 404


def test_login_unconfigured_vs_inactive_vs_unknown_org_are_indistinguishable(client):
    """Enumeration resistance: all three 404s must be identical in shape
    (same status code, same posture as sso_login's own precedent) so a
    caller can't distinguish "no SAML" from "SAML not active" from
    "unknown org" by response shape alone."""
    unknown_resp = _do_login_redirect(client, "totally-unknown-org-slug")

    no_config_org = _create_org(client, "Enum Test No Config Org")
    no_config_resp = _do_login_redirect(client, no_config_org["slug"])

    inactive_org = _create_org(client, "Enum Test Inactive Org")
    _plant_saml_config(inactive_org["id"], status="pending_verification")
    inactive_resp = _do_login_redirect(client, inactive_org["slug"])

    assert unknown_resp.status_code == no_config_resp.status_code == inactive_resp.status_code == 404


# ── 2. Successful redirect ───────────────────────────────────────────────


def test_login_active_config_redirects(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    assert resp.status_code in (302, 307)


def test_login_redirect_targets_configured_sso_url(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    location = resp.headers["location"]
    assert location.startswith("https://idp.example.com/sso?")


def test_login_redirect_contains_samlrequest(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert "SAMLRequest" in query
    assert len(query["SAMLRequest"][0]) > 20


def test_login_redirect_contains_relaystate(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert "RelayState" in query
    assert len(query["RelayState"][0]) > 20


def test_samlrequest_generated_successfully_via_python3_saml(client, org_with_active_saml):
    """The SAMLRequest is a genuine python3-saml-built AuthnRequest, not a
    hand-rolled string -- decode it (deflate + base64, the standard SAML
    HTTP-Redirect binding encoding) and confirm real AuthnRequest shape:
    correct root element, ID, Version, and a Destination matching the
    configured sso_url."""
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    root = _decode_authn_request(resp.headers["location"])

    assert root.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest"
    assert root.get("Version") == "2.0"
    assert root.get("ID")
    assert root.get("Destination") == "https://idp.example.com/sso"

    issuer = root.find("saml:Issuer", _AUTHN_REQUEST_NS)
    assert issuer is not None
    assert org_with_active_saml["org_slug"] in issuer.text
    assert issuer.text.endswith("/metadata")  # entity_id_for's own convention, PR3


def test_destination_corresponds_to_configured_sso_url_not_a_default(client):
    """A second org with a distinct sso_url produces an AuthnRequest whose
    Destination is THAT org's own configured value, not some shared
    constant -- proves the IdP URL genuinely comes from the resolved
    OrganizationSAMLConfig, not a hardcoded/default one."""
    org = _create_org(client, "Custom SSO URL Org")
    _plant_saml_config(org["id"], sso_url="https://custom-idp.example.org/saml/sso")
    resp = _do_login_redirect(client, org["slug"])
    root = _decode_authn_request(resp.headers["location"])
    assert root.get("Destination") == "https://custom-idp.example.org/saml/sso"


# ── 3. RelayState: tamper-resistance and binding ────────────────────────


def test_relaystate_binds_correct_organization_and_config(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    relay_state = parse_qs(urlparse(resp.headers["location"]).query)["RelayState"][0]
    claims = decode_token(relay_state)
    assert claims["type"] == "saml_relay_state"
    assert claims["organization_id"] == org_with_active_saml["org_id"]
    assert claims["organization_saml_config_id"] == org_with_active_saml["config_id"]


def test_relaystate_is_a_distinct_token_type_from_oidc_sso_state(client, org_with_active_saml):
    """Mirrors create_sso_state_token's own stated reasoning for being a
    distinct type from "oauth_state" -- a SAML RelayState token must not
    be structurally identical to (or accepted anywhere as) the existing
    OIDC "sso_state" token, precisely so it can never be replayed against
    /auth/sso/{org_slug}/callback."""
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    relay_state = parse_qs(urlparse(resp.headers["location"]).query)["RelayState"][0]
    claims = decode_token(relay_state)
    assert claims["type"] != "sso_state"
    assert claims["type"] != "oauth_state"


def test_relaystate_cannot_be_tampered_with(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    relay_state = parse_qs(urlparse(resp.headers["location"]).query)["RelayState"][0]

    # Flip a character in the payload segment of the JWT -- signature
    # must no longer verify.
    header, payload, signature = relay_state.split(".")
    tampered_char = "A" if payload[-1] != "A" else "B"
    tampered = f"{header}.{payload[:-1]}{tampered_char}.{signature}"

    with pytest.raises(Exception):
        decode_token(tampered)


def test_relaystate_with_wrong_signature_rejected(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    relay_state = parse_qs(urlparse(resp.headers["location"]).query)["RelayState"][0]
    header, payload, _signature = relay_state.split(".")
    forged = f"{header}.{payload}.forged-signature-not-real"

    with pytest.raises(Exception):
        decode_token(forged)


# ── 4. Multi-org isolation ───────────────────────────────────────────────


def test_two_organizations_produce_isolated_login_requests(client):
    org_a = _create_org(client, "SAML Login Org A")
    config_a_id = _plant_saml_config(org_a["id"], sso_url="https://idp-a.example.com/sso",
                                      entity_id="https://idp-a.example.com/entity")
    org_b = _create_org(client, "SAML Login Org B")
    config_b_id = _plant_saml_config(org_b["id"], sso_url="https://idp-b.example.com/sso",
                                      entity_id="https://idp-b.example.com/entity")

    resp_a = _do_login_redirect(client, org_a["slug"])
    resp_b = _do_login_redirect(client, org_b["slug"])

    root_a = _decode_authn_request(resp_a.headers["location"])
    root_b = _decode_authn_request(resp_b.headers["location"])

    # Different IdPs (Destination), different SP identity per org (Issuer
    # carries org_slug -- PR3's entity_id_for convention), different
    # AuthnRequest IDs (freshly generated per request, not reused).
    assert root_a.get("Destination") != root_b.get("Destination")
    assert root_a.find("saml:Issuer", _AUTHN_REQUEST_NS).text != root_b.find("saml:Issuer", _AUTHN_REQUEST_NS).text
    assert root_a.get("ID") != root_b.get("ID")

    relay_a = decode_token(parse_qs(urlparse(resp_a.headers["location"]).query)["RelayState"][0])
    relay_b = decode_token(parse_qs(urlparse(resp_b.headers["location"]).query)["RelayState"][0])
    assert relay_a["organization_id"] == org_a["id"]
    assert relay_b["organization_id"] == org_b["id"]
    assert relay_a["organization_saml_config_id"] == config_a_id
    assert relay_b["organization_saml_config_id"] == config_b_id
    assert relay_a["organization_id"] != relay_b["organization_id"]


def test_two_logins_for_same_org_produce_fresh_authn_request_ids(client, org_with_active_saml):
    """Each login attempt gets its own freshly-generated AuthnRequest ID
    -- not cached/reused across requests."""
    resp_1 = _do_login_redirect(client, org_with_active_saml["org_slug"])
    resp_2 = _do_login_redirect(client, org_with_active_saml["org_slug"])
    root_1 = _decode_authn_request(resp_1.headers["location"])
    root_2 = _decode_authn_request(resp_2.headers["location"])
    assert root_1.get("ID") != root_2.get("ID")


# ── 5. No secret/config leakage ──────────────────────────────────────────


def test_certificate_and_config_values_not_leaked_into_redirect_url(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    location = resp.headers["location"]
    assert "SENTINEL-CERT-SHOULD-NOT-LEAK" not in location

    root = _decode_authn_request(resp.headers["location"])
    raw_xml = etree.tostring(root).decode()
    assert "SENTINEL-CERT-SHOULD-NOT-LEAK" not in raw_xml


def test_relaystate_does_not_carry_the_certificate_or_raw_config(client, org_with_active_saml):
    resp = _do_login_redirect(client, org_with_active_saml["org_slug"])
    relay_state = parse_qs(urlparse(resp.headers["location"]).query)["RelayState"][0]
    claims = decode_token(relay_state)
    # request_id (PR5 addition): the AuthnRequest's own ID -- not
    # secret/config data, just what lets PR5's ACS handler validate
    # InResponseTo for real. See create_saml_relay_state_token's own
    # docstring.
    assert set(claims.keys()) <= {
        "type", "organization_id", "organization_saml_config_id", "request_id", "exp", "jti", "iss", "aud",
    }


# ── 6. PR3 metadata behavior remains intact ──────────────────────────────


def test_metadata_endpoint_still_works_for_org_with_saml_login_configured(client, org_with_active_saml):
    """Regression guard: PR4 must not have altered PR3's metadata
    endpoint behavior for the same organization."""
    resp = client.get(f"/auth/saml/{org_with_active_saml['org_slug']}/metadata")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/samlmetadata+xml")

    root = etree.fromstring(resp.content)
    assert org_with_active_saml["org_slug"] in root.get("entityID")
    # Same posture as before: metadata never reflects OrganizationSAMLConfig data.
    assert b"SENTINEL-CERT-SHOULD-NOT-LEAK" not in resp.content


def test_metadata_still_works_for_org_with_no_saml_config_at_all(client):
    """PR3's own defining behavior (metadata works before any config
    exists) must remain true even after PR4 adds a route that DOES
    require a config -- the two endpoints have deliberately different
    preconditions."""
    org = _create_org(client, "No Config Metadata Still Works Org")
    resp = client.get(f"/auth/saml/{org['slug']}/metadata")
    assert resp.status_code == 200
