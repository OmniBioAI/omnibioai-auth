"""SAML SSO PR5: ACS / assertion consumption and validation
(POST /auth/saml/{org_slug}/acs). Builds on PR2 (OrganizationSAMLConfig),
PR3 (SP metadata, XML escaping), and PR4 (SP-initiated login, RelayState
carrying request_id). Does NOT touch, and must not change the behavior
of, identity linking/JIT provisioning (PR6/PR7), CRUD (PR8), or the
existing OIDC SSO / OAuth / MFA flows -- see tests/test_sso_login.py and
tests/test_saml_login.py, both still run unmodified as part of the full
suite.

Tests construct REAL, genuinely-signed SAMLResponse documents (RSA
keypair + self-signed X.509 cert via `cryptography`, signed via
python3-saml's own OneLogin_Saml2_Utils.add_sign, which uses the real
xmlsec bindings PR1 installed) and drive them through the real,
unweakened validate_saml_response/OneLogin_Saml2_Auth.process_response
code path -- never a mocked/stubbed validator. This is the only way to
prove signature/audience/destination/recipient/issuer/InResponseTo/
timestamp validation is actually enforced, not just shaped like it is.
"""

import base64
import datetime
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import token_revocation
from app.core.jwt import decode_token
from app.db.models import OrganizationSAMLConfig
from app.services import org_saml_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


# ── Real IdP keypair/cert + signed-response fixture builder ────────────


def _generate_idp_keypair_and_cert(common_name="test-saml-idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


_SENTINEL = object()


def build_signed_saml_response(
    key_pem,
    cert_pem,
    *,
    idp_entity_id,
    sp_entity_id,
    acs_url,
    request_id,
    name_id="user@example.com",
    now=None,
    not_before_offset=-60,
    not_on_or_after_offset=300,
    audience=_SENTINEL,
    recipient=_SENTINEL,
    destination=_SENTINEL,
    issuer_override=None,
    in_response_to_override=_SENTINEL,
    sc_in_response_to_override=_SENTINEL,
    attributes=None,
    unsign=False,
):
    """Builds a real, signed (unless unsign=True) SAML Response, base64
    encoded exactly as the HTTP-POST binding requires. Only the
    Assertion is signed (not the outer Response) -- deliberately
    mirroring how real IdPs (Okta, Entra ID, ADFS) most commonly sign,
    and exactly what _ACS_SECURITY_SETTINGS (wantAssertionsSigned=True,
    wantMessagesSigned=False) expects.

    Every _SENTINEL-defaulted kwarg defaults to "the correct value for
    this SP/org" when not overridden, so a test only needs to override
    the ONE field it's trying to make wrong.
    """
    now = now or datetime.datetime.utcnow()
    audience = sp_entity_id if audience is _SENTINEL else audience
    recipient = acs_url if recipient is _SENTINEL else recipient
    destination = acs_url if destination is _SENTINEL else destination
    issuer = idp_entity_id if issuer_override is None else issuer_override
    in_response_to = request_id if in_response_to_override is _SENTINEL else in_response_to_override
    sc_in_response_to = request_id if sc_in_response_to_override is _SENTINEL else sc_in_response_to_override

    response_id = "_r" + uuid.uuid4().hex
    assertion_id = "_a" + uuid.uuid4().hex
    not_before = _fmt(now + datetime.timedelta(seconds=not_before_offset))
    not_on_or_after = _fmt(now + datetime.timedelta(seconds=not_on_or_after_offset))
    issue_instant = _fmt(now)

    in_response_to_attr = f' InResponseTo="{in_response_to}"' if in_response_to is not None else ""
    sc_in_response_to_attr = f' InResponseTo="{sc_in_response_to}"' if sc_in_response_to is not None else ""
    destination_attr = f' Destination="{destination}"' if destination is not None else ""
    recipient_attr = f' Recipient="{recipient}"' if recipient is not None else ""

    attr_statement = ""
    if attributes:
        attr_nodes = "".join(
            f'<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>'
            for name, value in attributes.items()
        )
        attr_statement = f"<saml:AttributeStatement>{attr_nodes}</saml:AttributeStatement>"

    assertion_xml = f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
<saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData{sc_in_response_to_attr} NotOnOrAfter="{not_on_or_after}"{recipient_attr}/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="_session1">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
{attr_statement}
</saml:Assertion>'''

    if unsign:
        signed_assertion = assertion_xml
    else:
        signed_assertion = OneLogin_Saml2_Utils.add_sign(assertion_xml, key_pem, cert_pem)
        if isinstance(signed_assertion, bytes):
            signed_assertion = signed_assertion.decode()

    response_xml = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}"{destination_attr}{in_response_to_attr}>
<saml:Issuer>{idp_entity_id}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
{signed_assertion}
</samlp:Response>'''

    return base64.b64encode(response_xml.encode()).decode()


# ── Redis mock for replay protection -- extends conftest's own pattern ──


@pytest.fixture(autouse=True)
def _replay_store(client, monkeypatch):
    """Real NX+EX semantics against an isolated per-test dict -- a
    correctly-behaving atomic "set if absent" fake, not a bare MagicMock
    (which would return a truthy-but-meaningless object for `.set(...)`
    and make replay rejection untestable). conftest.py's shared `client`
    fixture already patches token_revocation._blacklist for `.setex`/
    `.exists` (the access-token blacklist); this adds `.set` to the SAME
    mock object for the SAME connection PR5 deliberately reuses (see
    org_saml_service._reject_if_replayed's own docstring), isolated
    per-test (not session-shared like the blacklist's own dict) so replay
    tests don't leak state into each other.
    """
    store = {}

    def _set(key, value, nx=False, ex=None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    monkeypatch.setattr(token_revocation._blacklist, "set", _set, raising=False)
    yield store


# ── Org/user helpers (same convention as test_saml_login.py) ───────────


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-acs-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _create_org(client, name="SAML ACS Test Org"):
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
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(
            organization_id=org_id, entity_id=entity_id, sso_url=sso_url,
            x509_certificate=x509_certificate, status=status,
        )
        session.add(config)
        session.commit()
        session.refresh(config)
        return config.id
    finally:
        session.close()


@pytest.fixture
def idp_keys():
    return _generate_idp_keypair_and_cert()


@pytest.fixture
def org_with_saml_login(client, idp_keys):
    """A real org with a real, active OrganizationSAMLConfig whose
    x509_certificate is the REAL public cert matching idp_keys' private
    key -- and a real RelayState/request_id obtained by actually calling
    GET /auth/saml/{org_slug}/login (PR4's own merged, unmodified route),
    not fabricated. Everything a test needs to build a matching, real
    SAMLResponse and POST it to ACS."""
    _key_pem, cert_pem = idp_keys
    org = _create_org(client)
    idp_entity_id = "https://idp.example.com/entity"
    config_id = _plant_saml_config(org["id"], entity_id=idp_entity_id, x509_certificate=cert_pem)

    login_resp = client.get(f"/auth/saml/{org['slug']}/login", follow_redirects=False)
    assert login_resp.status_code in (302, 307)
    query = parse_qs(urlparse(login_resp.headers["location"]).query)
    relay_state = query["RelayState"][0]
    request_id = decode_token(relay_state)["request_id"]

    return {
        "org_id": org["id"],
        "org_slug": org["slug"],
        "config_id": config_id,
        "idp_entity_id": idp_entity_id,
        "sp_entity_id": org_saml_service.entity_id_for(org["slug"]),
        "acs_url": org_saml_service.acs_url_for(org["slug"]),
        "relay_state": relay_state,
        "request_id": request_id,
    }


def _post_acs(client, org_slug, saml_response_b64, relay_state=_SENTINEL):
    data = {"SAMLResponse": saml_response_b64}
    if relay_state is not _SENTINEL:
        data["RelayState"] = relay_state
    return client.post(f"/auth/saml/{org_slug}/acs", data=data)


def _build_valid_response(ctx, idp_keys, **overrides):
    key_pem, cert_pem = idp_keys
    return build_signed_saml_response(
        key_pem, cert_pem,
        idp_entity_id=ctx["idp_entity_id"],
        sp_entity_id=ctx["sp_entity_id"],
        acs_url=ctx["acs_url"],
        request_id=ctx["request_id"],
        **overrides,
    )


# ── 1. Organization / config resolution (before touching SAMLResponse) ──


def test_unknown_organization_fails_safely(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, "totally-unknown-org-slug", resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_missing_saml_configuration_fails_safely(client, idp_keys):
    org = _create_org(client, "ACS No Config Org")
    key_pem, cert_pem = idp_keys
    resp_body = build_signed_saml_response(
        key_pem, cert_pem, idp_entity_id="https://idp.example.com/entity",
        sp_entity_id=org_saml_service.entity_id_for(org["slug"]),
        acs_url=org_saml_service.acs_url_for(org["slug"]), request_id="ONELOGIN_fake",
    )
    resp = _post_acs(client, org["slug"], resp_body, "not-a-real-relay-state")
    assert resp.status_code == 400


def test_inactive_saml_configuration_fails_safely(client, org_with_saml_login, idp_keys):
    """The RelayState was minted while the config was active; flip it to
    inactive before ACS -- must be rejected even though the RelayState
    itself is validly signed and correctly bound."""
    session = _DirectSession()
    try:
        cfg = session.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.id == org_with_saml_login["config_id"]).first()
        cfg.status = "disabled"
        session.commit()
    finally:
        session.close()

    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 2. Malformed input ───────────────────────────────────────────────────


def test_missing_samlresponse_fails_safely(client, org_with_saml_login):
    resp = client.post(
        f"/auth/saml/{org_with_saml_login['org_slug']}/acs",
        data={"RelayState": org_with_saml_login["relay_state"]},
    )
    assert resp.status_code in (400, 422)  # FastAPI 422 for a missing required Form field


def test_malformed_samlresponse_fails_safely(client, org_with_saml_login):
    resp = _post_acs(client, org_with_saml_login["org_slug"], "not-valid-base64-xml!!!", org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 3. RelayState ─────────────────────────────────────────────────────────


def test_invalid_relaystate_fails_safely(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, "not-a-real-relay-state-token")
    assert resp.status_code == 400


def test_missing_relaystate_fails_safely(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = client.post(
        f"/auth/saml/{org_with_saml_login['org_slug']}/acs", data={"SAMLResponse": resp_body}
    )
    assert resp.status_code == 400


def test_tampered_relaystate_rejected(client, org_with_saml_login, idp_keys):
    relay_state = org_with_saml_login["relay_state"]
    header, payload, signature = relay_state.split(".")
    tampered_char = "A" if payload[-1] != "A" else "B"
    tampered = f"{header}.{payload[:-1]}{tampered_char}.{signature}"

    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, tampered)
    assert resp.status_code == 400


def test_relaystate_for_another_organization_rejected(client, org_with_saml_login, idp_keys):
    other_org = _create_org(client, "ACS Other Org For RelayState")
    _plant_saml_config(other_org["id"])

    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    # Valid RelayState, but for a DIFFERENT organization than org_slug names.
    resp = _post_acs(client, other_org["slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_relaystate_for_another_saml_configuration_rejected(client, org_with_saml_login, idp_keys):
    """Same organization, but the RelayState's committed
    organization_saml_config_id no longer matches the org's actual
    current config (simulates the config having been replaced)."""
    session = _DirectSession()
    try:
        old_cfg = session.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.id == org_with_saml_login["config_id"]).first()
        session.delete(old_cfg)
        session.commit()
    finally:
        session.close()
    _plant_saml_config(org_with_saml_login["org_id"], entity_id=org_with_saml_login["idp_entity_id"])

    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 4. Signature / trust anchor ──────────────────────────────────────────


def test_invalid_signature_rejected(client, org_with_saml_login, idp_keys):
    """Signed with a DIFFERENT private key than the one whose cert is
    registered in OrganizationSAMLConfig -- proves signature verification
    is real, not a shape check (same convention as
    tests/test_sso_login.py's test_callback_invalid_signature_rejected)."""
    attacker_key_pem, attacker_cert_pem = _generate_idp_keypair_and_cert("attacker-idp")
    resp_body = build_signed_saml_response(
        attacker_key_pem, attacker_cert_pem,
        idp_entity_id=org_with_saml_login["idp_entity_id"],
        sp_entity_id=org_with_saml_login["sp_entity_id"],
        acs_url=org_with_saml_login["acs_url"],
        request_id=org_with_saml_login["request_id"],
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_wrong_idp_certificate_rejected(client, org_with_saml_login):
    """The response is genuinely signed and otherwise fully correct, but
    OrganizationSAMLConfig.x509_certificate (the trust anchor) has been
    changed to a DIFFERENT, unrelated cert since the assertion was
    signed -- must be rejected: this SP never trusts a certificate
    supplied in the SAMLResponse itself, only the one on file."""
    _wrong_key_pem, wrong_cert_pem = _generate_idp_keypair_and_cert("unrelated-idp")
    session = _DirectSession()
    try:
        cfg = session.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.id == org_with_saml_login["config_id"]).first()
        cfg.x509_certificate = wrong_cert_pem
        session.commit()
    finally:
        session.close()

    real_key_pem, real_cert_pem = _generate_idp_keypair_and_cert()
    # Assertion is signed with a DIFFERENT key than the (now-swapped)
    # trust anchor expects.
    resp_body = build_signed_saml_response(
        real_key_pem, real_cert_pem,
        idp_entity_id=org_with_saml_login["idp_entity_id"],
        sp_entity_id=org_with_saml_login["sp_entity_id"],
        acs_url=org_with_saml_login["acs_url"],
        request_id=org_with_saml_login["request_id"],
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_unsigned_assertion_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, unsign=True)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 5. Issuer / audience / destination / recipient ──────────────────────


def test_wrong_issuer_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, issuer_override="https://evil-idp.example.com")
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_wrong_audience_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, audience="https://someone-else.example.com")
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_wrong_destination_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(
        org_with_saml_login, idp_keys, destination="https://webstudio.omnibioai.org/auth/saml/some-other-org/acs"
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_wrong_recipient_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(
        org_with_saml_login, idp_keys, recipient="https://webstudio.omnibioai.org/auth/saml/some-other-org/acs"
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 6. InResponseTo ───────────────────────────────────────────────────────


def test_invalid_inresponseto_response_level_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, in_response_to_override="ONELOGIN_completely_different")
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_invalid_inresponseto_subject_confirmation_level_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, sc_in_response_to_override="ONELOGIN_completely_different")
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 7. Time validity ───────────────────────────────────────────────────────


def test_expired_assertion_rejected(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(
        org_with_saml_login, idp_keys, not_on_or_after_offset=-600, not_before_offset=-900
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


def test_not_yet_valid_assertion_rejected(client, org_with_saml_login, idp_keys):
    """Beyond python3-saml's own 300-second (ALLOWED_CLOCK_DRIFT) skew
    allowance on Conditions/NotBefore -- verified empirically (see
    org_saml_service.validate_saml_response's own docstring) that
    anything under 300s in the future is deliberately tolerated, so this
    uses 600s to unambiguously exceed it."""
    resp_body = _build_valid_response(
        org_with_saml_login, idp_keys, not_before_offset=600, not_on_or_after_offset=900
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400


# ── 8. Replay ───────────────────────────────────────────────────────────


def test_replay_of_previously_accepted_assertion_rejected(client, org_with_saml_login, idp_keys):
    """The IMPORTANT boundary this test proves: the FIRST use gets past
    every validation check (reaches PR5's own architectural stop -- 501,
    not 400 -- see test_valid_assertion_stops_at_linking_boundary), and
    only the SECOND, replayed use of the exact same assertion is
    rejected as a replay specifically."""
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)

    first = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert first.status_code == 501  # validated fine; stops at the linking boundary, not a validation failure

    second = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert second.status_code == 400  # same assertion, rejected as a replay this time


# ── 9. Identity pipeline boundary ─────────────────────────────────────────


def test_valid_assertion_stops_at_linking_boundary(client, org_with_saml_login, idp_keys):
    """The core architectural-boundary test: a fully valid, correctly
    signed, correctly bound assertion must NOT produce an access_token
    or refresh_token -- PR6/PR7's OAuthAccount schema work is a
    prerequisite this PR does not invent around. 501, not 200/400: the
    assertion itself was valid (not a client error), but this
    deployment cannot complete authentication with it yet."""
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])

    assert resp.status_code == 501
    assert "access_token" not in resp.text
    assert "refresh_token" not in resp.text


def test_valid_assertion_with_attributes_still_stops_at_linking_boundary(client, org_with_saml_login, idp_keys):
    """Same boundary, but with a real AttributeStatement present too --
    proves attribute extraction doesn't accidentally become a path
    around the linking boundary."""
    resp_body = _build_valid_response(org_with_saml_login, idp_keys, attributes={"department": "Engineering"})
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 501
    assert "access_token" not in resp.text


# ── 10. No sensitive data leakage ────────────────────────────────────────


def test_no_certificate_or_raw_assertion_leaks_in_error_responses(client, org_with_saml_login, idp_keys):
    """Every rejection path's response body must never contain the IdP
    certificate, the raw base64 SAMLResponse, or python3-saml's internal
    error/exception text."""
    wrong_key_pem, wrong_cert_pem = _generate_idp_keypair_and_cert("attacker")
    resp_body = build_signed_saml_response(
        wrong_key_pem, wrong_cert_pem,
        idp_entity_id=org_with_saml_login["idp_entity_id"],
        sp_entity_id=org_with_saml_login["sp_entity_id"],
        acs_url=org_with_saml_login["acs_url"],
        request_id=org_with_saml_login["request_id"],
    )
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert resp.status_code == 400
    assert "SENTINEL-CERT-SHOULD-NOT-LEAK" not in resp.text
    assert "-----BEGIN CERTIFICATE-----" not in resp.text
    assert resp_body not in resp.text
    assert "xmlsec" not in resp.text.lower()
    assert "traceback" not in resp.text.lower()


def test_no_leakage_on_successful_validation_stopped_at_boundary(client, org_with_saml_login, idp_keys):
    resp_body = _build_valid_response(org_with_saml_login, idp_keys)
    resp = _post_acs(client, org_with_saml_login["org_slug"], resp_body, org_with_saml_login["relay_state"])
    assert "SENTINEL-CERT-SHOULD-NOT-LEAK" not in resp.text
    assert "user@example.com" not in resp.text  # NameID itself not echoed back either


# ── 11. Cross-organization isolation ─────────────────────────────────────


def test_two_organizations_cannot_consume_each_others_saml_responses(client, idp_keys):
    org_a = _create_org(client, "ACS Isolation Org A")
    key_a, cert_a = idp_keys
    idp_a = "https://idp-a.example.com/entity"
    _plant_saml_config(org_a["id"], entity_id=idp_a, sso_url="https://idp-a.example.com/sso", x509_certificate=cert_a)

    org_b = _create_org(client, "ACS Isolation Org B")
    _key_b, cert_b = _generate_idp_keypair_and_cert("idp-b")
    idp_b = "https://idp-b.example.com/entity"
    _plant_saml_config(org_b["id"], entity_id=idp_b, sso_url="https://idp-b.example.com/sso", x509_certificate=cert_b)

    login_a = client.get(f"/auth/saml/{org_a['slug']}/login", follow_redirects=False)
    relay_a = parse_qs(urlparse(login_a.headers["location"]).query)["RelayState"][0]
    request_id_a = decode_token(relay_a)["request_id"]

    # A genuinely valid response FOR ORG A...
    resp_body_a = build_signed_saml_response(
        key_a, cert_a, idp_entity_id=idp_a,
        sp_entity_id=org_saml_service.entity_id_for(org_a["slug"]),
        acs_url=org_saml_service.acs_url_for(org_a["slug"]), request_id=request_id_a,
    )

    # ...must be rejected when POSTed to Org B's ACS endpoint, even with
    # Org A's own (validly signed) RelayState -- _verify_saml_relay_state
    # itself rejects this at the org-consistency-check stage before the
    # SAMLResponse is even validated.
    resp = _post_acs(client, org_b["slug"], resp_body_a, relay_a)
    assert resp.status_code == 400

    # And Org A's real, correct flow still succeeds through validation
    # (reaches the 501 linking boundary, not a 400) -- proves the 400
    # above is genuine cross-org isolation, not a broken fixture.
    resp_own = _post_acs(client, org_a["slug"], resp_body_a, relay_a)
    assert resp_own.status_code == 501


# ── 12. Existing OIDC/OAuth/JWT/MFA behavior unaffected ─────────────────


def test_existing_oidc_sso_login_route_unaffected(client):
    """Smoke check within this file too: PR4's own login route (and by
    extension the OIDC SSO stack it doesn't touch) still works exactly
    as before -- full regression is tests/test_sso_login.py +
    tests/test_saml_login.py, run separately."""
    resp = client.get("/auth/sso/does-not-exist-org/login", follow_redirects=False)
    assert resp.status_code == 404


def test_existing_saml_metadata_and_login_routes_unaffected(client, org_with_saml_login):
    metadata_resp = client.get(f"/auth/saml/{org_with_saml_login['org_slug']}/metadata")
    assert metadata_resp.status_code == 200

    login_resp = client.get(f"/auth/saml/{org_with_saml_login['org_slug']}/login", follow_redirects=False)
    assert login_resp.status_code in (302, 307)
    assert "SAMLRequest" in login_resp.headers["location"]
