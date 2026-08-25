"""#263: per-org SAML enforcement. Mirrors tests/test_sso_enforcement.py
(Phase 2 PR5's OIDC enforcement suite) as closely as possible -- same
lockout-guard, password-rejection, OAuth-bypass, and tenant-isolation
coverage, ported to SAML's real signed-SAMLResponse login flow instead of
OIDC's id_token flow. Deliberately does NOT mirror that file's break-glass
override tests: OrganizationSAMLConfig has no override mechanism at all,
a disclosed, out-of-scope difference (see app/services/org_saml_service.py's
own section comment on set_enforced) -- there is nothing for a bypass to
suspend or a test to exercise.
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

from app.core.jwt import decode_token
from app.services import oauth_service, org_saml_service

_KID = "saml-enforce-test-key-1"


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-enforce-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


# ── Real IdP keypair/cert + signed-response fixture builder ────────────
# Copied from tests/test_saml_jit_provisioning.py (that file's own module
# docstring explains why every SAML test file drives real signed
# documents through the real, unweakened validate_saml_response path
# rather than a mock -- same convention followed here).


def _generate_idp_keypair_and_cert(common_name="saml-enforce-test-idp"):
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


def build_signed_saml_response(
    key_pem, cert_pem, *, idp_entity_id, sp_entity_id, acs_url, request_id,
    name_id="user@example.com", attributes=None,
):
    now = datetime.datetime.utcnow()
    response_id = "_r" + uuid.uuid4().hex
    assertion_id = "_a" + uuid.uuid4().hex
    not_before = _fmt(now - datetime.timedelta(seconds=60))
    not_on_or_after = _fmt(now + datetime.timedelta(seconds=300))
    issue_instant = _fmt(now)

    attr_statement = ""
    if attributes:
        attr_nodes = "".join(
            f'<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>'
            for name, value in attributes.items()
        )
        attr_statement = f"<saml:AttributeStatement>{attr_nodes}</saml:AttributeStatement>"

    name_id_node = f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>' if name_id is not None else ""

    assertion_xml = f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
<saml:Issuer>{idp_entity_id}</saml:Issuer>
<saml:Subject>
{name_id_node}
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
<saml:AudienceRestriction><saml:Audience>{sp_entity_id}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="_session1">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
{attr_statement}
</saml:Assertion>'''

    signed_assertion = OneLogin_Saml2_Utils.add_sign(assertion_xml, key_pem, cert_pem)
    if isinstance(signed_assertion, bytes):
        signed_assertion = signed_assertion.decode()

    response_xml = f'''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{acs_url}" InResponseTo="{request_id}">
<saml:Issuer>{idp_entity_id}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
{signed_assertion}
</samlp:Response>'''

    return base64.b64encode(response_xml.encode()).decode()


@pytest.fixture(autouse=True)
def _replay_store(client, monkeypatch):
    """Same technique as the other SAML test files' fixture of this name
    -- real NX+EX semantics against an isolated per-test dict, since
    _reject_if_replayed is exercised for real here too."""
    from app.core import token_revocation

    store = {}

    def _set(key, value, nx=False, ex=None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    monkeypatch.setattr(token_revocation._blacklist, "set", _set, raising=False)
    yield store


@pytest.fixture
def idp_keys():
    return _generate_idp_keypair_and_cert()


@pytest.fixture
def org_with_saml(client, idp_keys):
    """Mirrors test_sso_enforcement.py's org_with_sso fixture exactly --
    unique domain per test invocation for the same cross-test-collision
    reason that file's own comment documents (test.db persists across the
    whole session)."""
    key_pem, cert_pem = idp_keys
    unique = uuid.uuid4().hex[:8]
    idp_entity_id = f"https://idp.saml-enforce-test-{unique}.example.com/entity"
    sso_url = f"https://idp.saml-enforce-test-{unique}.example.com/sso"
    domain = f"saml-enforce-test-{unique}.example.com"

    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "SAML Enforcement Test Org", "slug": f"saml-enforce-org-{unique}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{org['id']}/saml",
        json={
            "entity_id": idp_entity_id,
            "sso_url": sso_url,
            "x509_certificate": cert_pem,
            "allowed_domains": [domain],
        },
        headers=headers,
    ).json()
    return {
        "org_id": org["id"], "org_slug": org["slug"], "owner": owner, "owner_headers": headers,
        "config": created, "idp_entity_id": idp_entity_id, "domain": domain,
        "key_pem": key_pem, "cert_pem": cert_pem,
    }


def _complete_one_saml_login(client, org, email=None):
    """Drives a full, real login through /auth/saml -- this is how the
    lockout guard gets satisfied (an actual OAuthAccount row must exist),
    same mechanism test_sso_enforcement.py's _complete_one_sso_login uses
    for OIDC."""
    email = email or f"member-{uuid.uuid4().hex[:8]}@{org['domain']}"

    login_resp = client.get(f"/auth/saml/{org['org_slug']}/login", follow_redirects=False)
    assert login_resp.status_code in (302, 307)
    relay_state = parse_qs(urlparse(login_resp.headers["location"]).query)["RelayState"][0]
    request_id = decode_token(relay_state)["request_id"]

    sp_entity_id = org_saml_service.entity_id_for(org["org_slug"])
    acs_url = org_saml_service.acs_url_for(org["org_slug"])
    saml_response_b64 = build_signed_saml_response(
        org["key_pem"], org["cert_pem"],
        idp_entity_id=org["idp_entity_id"], sp_entity_id=sp_entity_id, acs_url=acs_url,
        request_id=request_id, name_id=email,
    )

    resp = client.post(
        f"/auth/saml/{org['org_slug']}/acs",
        data={"SAMLResponse": saml_response_b64, "RelayState": relay_state},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    return resp, email


def _enable_enforcement(client, org):
    _complete_one_saml_login(client, org)
    resp = client.patch(f"/orgs/{org['org_id']}/saml", json={"enforced": True}, headers=org["owner_headers"])
    assert resp.status_code == 200
    return resp.json()


# ── Lockout guard ────────────────────────────────────────────────────────────


def test_enforced_true_rejected_without_prior_saml_login(client, org_with_saml):
    resp = client.patch(
        f"/orgs/{org_with_saml['org_id']}/saml", json={"enforced": True}, headers=org_with_saml["owner_headers"]
    )
    assert resp.status_code == 400
    assert "at least one member" in resp.json()["detail"]

    check = client.get(f"/orgs/{org_with_saml['org_id']}/saml", headers=org_with_saml["owner_headers"])
    assert check.json()["enforced"] is False


def test_enforced_true_succeeds_after_a_completed_saml_login(client, org_with_saml):
    _complete_one_saml_login(client, org_with_saml)

    resp = client.patch(
        f"/orgs/{org_with_saml['org_id']}/saml", json={"enforced": True}, headers=org_with_saml["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["enforced"] is True


def test_enforced_can_be_disabled_without_the_lockout_guard(client, org_with_saml):
    _enable_enforcement(client, org_with_saml)

    resp = client.patch(
        f"/orgs/{org_with_saml['org_id']}/saml", json={"enforced": False}, headers=org_with_saml["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["enforced"] is False

    member = _register_and_login(client, email=f"henry-{uuid.uuid4().hex[:8]}@{org_with_saml['domain']}")
    resp2 = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp2.status_code == 200


# ── Password login rejection, without ever checking the password ──────────


def test_password_login_rejected_without_calling_verify_password(client, org_with_saml, monkeypatch):
    # Registered (and logged in once, successfully) *before* enforcement
    # is turned on -- an existing password account that predates the
    # org enforcing SAML, exactly the case enforcement must still catch.
    member = _register_and_login(client, email=f"carol-{uuid.uuid4().hex[:8]}@{org_with_saml['domain']}")
    _enable_enforcement(client, org_with_saml)

    call_count = {"n": 0}
    import app.services.auth_service as auth_service_module

    def spy_verify_password(*args, **kwargs):
        call_count["n"] += 1
        return True  # would incorrectly succeed if ever reached

    monkeypatch.setattr(auth_service_module, "verify_password", spy_verify_password)

    resp = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["reason"] == "sso_required"
    assert detail["org_slug"] == org_with_saml["org_slug"]
    assert detail["sso_login_url"] == f"/auth/saml/{org_with_saml['org_slug']}/login"
    assert call_count["n"] == 0  # verify_password never reached


def test_password_login_still_works_with_wrong_domain_email(client, org_with_saml):
    """Sanity: enforcement is domain-scoped, an unrelated email is
    unaffected by this org's enforcement."""
    _enable_enforcement(client, org_with_saml)
    outsider = _register_and_login(client, email=f"outside-{uuid.uuid4().hex[:8]}@totally-different.test")
    resp = client.post("/auth/login", json={"email": outsider["email"], "password": outsider["password"]})
    assert resp.status_code == 200


# ── Not bypassable via Google/GitHub/Microsoft ──────────────────────────────


def test_google_oauth_login_rejected_for_enforced_org_member(client, org_with_saml, monkeypatch):
    _enable_enforcement(client, org_with_saml)

    from app.core.jwt import create_oauth_state_token
    from app.core.oauth_providers import PROVIDERS

    PROVIDERS["google"]["client_id"] = "test-google-client-id"
    PROVIDERS["google"]["client_secret"] = "test-google-client-secret"

    email = f"dave-{uuid.uuid4().hex[:8]}@{org_with_saml['domain']}"

    async def fake_exchange(provider, code, code_verifier=None):
        return "google-uid-saml-enforce-bypass-attempt", email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)

    state = create_oauth_state_token("google")
    resp = client.post("/auth/google/callback", json={"code": "fake", "state": state})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sso_required"
    assert resp.json()["detail"]["sso_login_url"] == f"/auth/saml/{org_with_saml['org_slug']}/login"


# ── Tenant isolation ──────────────────────────────────────────────────────────


def test_non_enforced_org_user_unaffected_by_other_orgs_saml_enforcement(client, org_with_saml, idp_keys):
    _enable_enforcement(client, org_with_saml)

    _, other_cert_pem = _generate_idp_keypair_and_cert("other-saml-org-idp")
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    other_org = client.post(
        "/orgs", json={"name": "Non-Enforcing SAML Org", "slug": f"non-enforce-saml-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    client.post(
        f"/orgs/{other_org['id']}/saml",
        json={
            "entity_id": "https://idp.other-saml-org-test.example.com/entity",
            "sso_url": "https://idp.other-saml-org-test.example.com/sso",
            "x509_certificate": other_cert_pem,
            "allowed_domains": ["other-saml-org-test.example.com"],
        },
        headers=headers,
    )

    member = _register_and_login(client, email=f"frank-{uuid.uuid4().hex[:8]}@other-saml-org-test.example.com")
    resp = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp.status_code == 200  # unaffected -- different org, never enforced


# ── allowed_domains resolution (SAML-specific: this column is new, #263) ────


def test_login_unaffected_before_allowed_domains_configured(client):
    """An org with no SAML config at all (or one whose domain doesn't
    match) must never affect an unrelated login -- sanity check that
    find_enforced_saml_org_for_email fails closed (returns None), not
    open, when nothing matches."""
    member = _register_and_login(client, email=f"nomatch-{uuid.uuid4().hex[:8]}@no-org-claims-this.test")
    resp = client.post("/auth/login", json={"email": member["email"], "password": member["password"]})
    assert resp.status_code == 200
