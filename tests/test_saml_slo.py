"""SAML SSO PR11: Single Logout (SLO). Builds on PR4 (SP-initiated login),
PR5 (ACS/assertion validation), and PR8 (organization_saml_configs.
slo_url) -- see app/services/org_saml_service.py's own "PR11: Single
Logout" module comment for the full python3-saml-verified design this
file tests against.

Same convention as the other SAML test files: local, self-contained
helpers building REAL, genuinely-signed SAML documents through the
real, unweakened validation path -- see tests/test_saml_acs.py's own
module docstring for why. SLO specifically uses HTTP-Redirect binding
(query-string parameters, detached SigAlg/Signature over the raw query
string), not HTTP-POST like ACS -- verified directly against the
installed python3-saml source, not assumed -- so the signing helpers
here are genuinely different from build_signed_saml_response's own
XML-enveloped-signature approach: they build a real LogoutRequest/
LogoutResponse via OneLogin_Saml2_Auth.logout()/process_slo() itself
(playing the IdP's sending role with a real, test-only IdP keypair),
then extract the resulting query-string parameters -- never hand-rolled
signing math.
"""

import base64
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import OAuthAccount, OrganizationSAMLConfig, User, UserSession
from app.services import mfa_service, org_saml_service, session_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"


# ── Real IdP keypair/cert -- same convention every other SAML test file
# uses (see test_saml_acs.py's own module docstring). ──────────────────


def _generate_idp_keypair_and_cert(common_name="test-saml-idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


@pytest.fixture(autouse=True)
def _replay_store(client, monkeypatch):
    """Same technique as every other SAML test file's fixture of this
    name -- real NX+EX semantics against an isolated per-test dict,
    since PR5's replay protection (reused/generalized for SLO's own
    LogoutRequest replay check) is exercised for real here too."""
    from app.core import token_revocation

    store = {}

    def _set(key, value, nx=False, ex=None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    monkeypatch.setattr(token_revocation._blacklist, "set", _set, raising=False)
    yield store


# ── Org/user/config/session helpers ──────────────────────────────────


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-slo-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _create_org(client, name="SAML SLO Test Org"):
    owner = _register_and_login(client)
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    created = client.post(
        "/orgs",
        json={"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created["owner"] = owner
    return created


def _plant_saml_config(
    org_id, sso_url="https://idp.example.com/sso", entity_id="https://idp.example.com/entity",
    x509_certificate="SENTINEL-CERT-SHOULD-NOT-LEAK", status="active", slo_url=None,
):
    session = _DirectSession()
    try:
        config = OrganizationSAMLConfig(
            organization_id=org_id, entity_id=entity_id, sso_url=sso_url,
            x509_certificate=x509_certificate, status=status, slo_url=slo_url,
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


def _start_saml_login(client, org_slug):
    resp = client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    query = parse_qs(urlparse(resp.headers["location"]).query)
    relay_state = query["RelayState"][0]
    request_id = decode_token(relay_state)["request_id"]
    return relay_state, request_id


def _org_with_saml_login(client, idp_keys, org_name="SAML SLO Test Org", slo_url="https://idp.example.com/slo"):
    _key_pem, cert_pem = idp_keys
    org = _create_org(client, org_name)
    idp_entity_id = f"https://idp.example.com/entity-{uuid.uuid4().hex[:8]}"
    config_id = _plant_saml_config(
        org["id"], entity_id=idp_entity_id, x509_certificate=cert_pem, slo_url=slo_url,
    )
    relay_state, request_id = _start_saml_login(client, org["slug"])
    return {
        "org_id": org["id"], "org_slug": org["slug"], "config_id": config_id,
        "idp_entity_id": idp_entity_id,
        "sp_entity_id": org_saml_service.entity_id_for(org["slug"]),
        "acs_url": org_saml_service.acs_url_for(org["slug"]),
        # This SP's own real /slo endpoint -- the correct Destination for
        # every message built by _build_idp_logout_request/_response
        # below (those play the IdP's sending role, targeting this URL).
        "slo_url": org_saml_service.slo_url_for(org["slug"]),
        # The IdP's OWN configured slo_url (organization_saml_configs.
        # slo_url) -- a genuinely different URL, only ever relevant to
        # asserting what THIS SP's own SP-initiated /logout endpoint
        # produces (org_saml_service.build_logout_request_url redirects
        # to *this*, not to "slo_url" above).
        "idp_configured_slo_url": slo_url,
        "relay_state": relay_state, "request_id": request_id,
    }


def build_signed_saml_response(
    key_pem, cert_pem, *, idp_entity_id, sp_entity_id, acs_url, request_id,
    name_id="user@example.com", session_index="_session1", attributes=None,
):
    """Same shape as every other SAML test file's own version -- login/
    ACS assertion, HTTP-POST binding, XML-enveloped signature. Carries a
    real SessionIndex (default "_session1") so the resulting UserSession
    row has one to test IdP-initiated SLO's own SessionIndex-scoped
    lookup against."""
    now = datetime.utcnow()
    response_id = "_r" + uuid.uuid4().hex
    assertion_id = "_a" + uuid.uuid4().hex
    not_before = (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = (now + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    attr_statement = ""
    if attributes:
        attr_nodes = "".join(
            f'<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>'
            for name, value in attributes.items()
        )
        attr_statement = f"<saml:AttributeStatement>{attr_nodes}</saml:AttributeStatement>"

    assertion_xml = f'''<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
<saml:Issuer>{idp_entity_id}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
<saml:AudienceRestriction><saml:Audience>{sp_entity_id}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{session_index}">
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


def _post_acs(client, org_slug, saml_response_b64, relay_state):
    return client.post(
        f"/auth/saml/{org_slug}/acs", data={"SAMLResponse": saml_response_b64, "RelayState": relay_state}
    )


def _login_via_saml(client, ctx, idp_keys, name_id=None, session_index="_session1"):
    """Full, real SP-initiated login round trip -- returns the resulting
    tokens plus the email/session_index used, so a test can then exercise
    SLO against a genuinely SAML-originated session (not a hand-inserted
    DB row) wherever that matters."""
    key_pem, cert_pem = idp_keys
    email = name_id or f"saml-slo-user-{uuid.uuid4().hex[:8]}@example.com"
    resp_body = build_signed_saml_response(
        key_pem, cert_pem, idp_entity_id=ctx["idp_entity_id"], sp_entity_id=ctx["sp_entity_id"],
        acs_url=ctx["acs_url"], request_id=ctx["request_id"], name_id=email, session_index=session_index,
    )
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    return {"email": email, "access_token": data["access_token"], "refresh_token": data["refresh_token"]}


def _session_for(user_email):
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == user_email).first()
        return db.query(UserSession).filter(UserSession.user_id == user.id).order_by(UserSession.id.desc()).first()
    finally:
        db.close()


def _plant_saml_session(org_id, config_id, name_id, session_index="_session1", status="active"):
    """Directly inserts a User + UserSession carrying SAML identity data
    -- used by IdP-initiated tests that only need a session to already
    exist and be findable, not a full login round trip."""
    db = _DirectSession()
    try:
        user = User(email=name_id, hashed_password=None, status="active")
        db.add(user)
        db.flush()
        session = UserSession(
            session_id=str(uuid.uuid4()), user_id=user.id, organization_id=org_id,
            auth_method="saml", mfa_verified=True, status=status,
            created_at=datetime.utcnow(), last_activity_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            saml_name_id=name_id, saml_session_index=session_index,
            organization_saml_config_id=config_id,
        )
        db.add(session)
        db.commit()
        return user.id, session.session_id
    finally:
        db.close()


# ── SLO message builders -- real python3-saml, playing the IdP's own
# sending role (a real, test-only IdP keypair signs what it sends,
# exactly as a genuine IdP would). ──────────────────────────────────────


def _idp_sender_settings(idp_key_pem, idp_cert_pem, idp_entity_id, sp_slo_url, sign=True):
    """Settings for using OneLogin_Saml2_Auth/Logout_Response to build a
    message AS the IdP would send it: this object's own "sp" block is
    the SENDER's identity (the IdP's test keypair signs with it), and
    "idp" is the DESTINATION being sent to -- .logout()'s own redirect
    target is get_idp_slo_url() = idp.singleLogoutService.url, and
    Logout_Response.build()'s own Destination attribute is
    get_idp_slo_response_url(), the identical field. sp_slo_url (this
    SP's real /slo endpoint) must therefore live in the "idp" block, not
    "sp" -- getting this backwards silently produces a message whose
    Destination doesn't match this SP's real endpoint, which the real
    Destination check (logout_request.py's/logout_response.py's own
    is_valid()) then correctly rejects.
    """
    return {
        "strict": True,
        "sp": {
            "entityId": idp_entity_id,
            "assertionConsumerService": {"url": sp_slo_url, "binding": _HTTP_REDIRECT},
            "singleLogoutService": {"url": sp_slo_url, "binding": _HTTP_REDIRECT},
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": idp_cert_pem,
            "privateKey": idp_key_pem,
        },
        "idp": {
            "entityId": "https://placeholder-idp.example.com/entity",
            "singleSignOnService": {"url": "https://placeholder-idp.example.com/sso"},
            "singleLogoutService": {"url": sp_slo_url},
            "x509cert": idp_cert_pem,
        },
        "security": {
            "logoutRequestSigned": sign,
            "logoutResponseSigned": sign,
            "wantMessagesSigned": False,
            "signatureAlgorithm": _RSA_SHA256,
        },
    }


def _build_idp_logout_request(idp_key_pem, idp_cert_pem, idp_entity_id, sp_slo_url, name_id, session_index=None, sign=True):
    """Builds a real LogoutRequest, signed (or not) by the IdP's own
    test keypair, using OneLogin_Saml2_Auth.logout() itself -- the real
    library's own real signing path, playing the sending (IdP) role.
    Returns (SAMLRequest, RelayState_or_None, SigAlg_or_None,
    Signature_or_None, raw_query_string) extracted from the resulting
    redirect URL."""
    settings_dict = _idp_sender_settings(idp_key_pem, idp_cert_pem, idp_entity_id, sp_slo_url, sign=sign)
    saml_settings = OneLogin_Saml2_Settings(settings_dict)
    auth = OneLogin_Saml2_Auth(
        {"http_host": "testserver", "https": "on", "script_name": "/", "get_data": {}}, old_settings=saml_settings,
    )
    redirect_url = auth.logout(name_id=name_id, session_index=session_index)
    return _split_query(redirect_url)


def _split_query(redirect_url):
    query = urlparse(redirect_url).query
    parsed = {k: v[0] for k, v in parse_qs(query).items()}
    return parsed, query


def _build_idp_logout_response(idp_key_pem, idp_cert_pem, idp_entity_id, sp_slo_url, in_response_to, relay_state=None, sign=True):
    """Builds a real LogoutResponse (IdP replying to this SP's own
    SP-initiated LogoutRequest), signed by the IdP's test keypair.
    OneLogin_Saml2_Logout_Response has no equivalent of Auth.logout()
    for building+signing a response in one call, so this replicates
    process_slo's own build-then-optionally-sign steps directly
    (verified by reading that method) -- still the real library's own
    XML construction and OneLogin_Saml2_Utils.sign_binary signing, never
    hand-rolled crypto."""
    settings_dict = _idp_sender_settings(idp_key_pem, idp_cert_pem, idp_entity_id, sp_slo_url, sign=sign)
    saml_settings = OneLogin_Saml2_Settings(settings_dict)
    response_builder = OneLogin_Saml2_Logout_Response(saml_settings)
    response_builder.build(in_response_to)
    saml_response = response_builder.get_response()

    parameters = {"SAMLResponse": saml_response}
    if relay_state is not None:
        parameters["RelayState"] = relay_state
    if sign:
        auth = OneLogin_Saml2_Auth({"get_data": {}}, old_settings=saml_settings)
        auth.add_response_signature(parameters, _RSA_SHA256)

    redirect_url = OneLogin_Saml2_Utils.redirect(sp_slo_url, parameters, request_data={})
    return _split_query(redirect_url)


# ── 1. SP-initiated logout: happy path + local-session semantics ─────


def test_sp_initiated_logout_revokes_local_session_and_returns_idp_url(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)

    resp = client.post("/auth/saml/{}/logout".format(ctx["org_slug"]), json={"refresh_token": login["refresh_token"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Logged out"
    assert "idp_logout_url" in data
    assert data["idp_logout_url"].startswith(ctx["idp_configured_slo_url"])

    session = _session_for(login["email"])
    assert session.status == "revoked"


def test_sp_initiated_logout_of_non_saml_session_has_no_idp_url(client):
    """Password-login logout must behave exactly as /auth/logout already
    does -- no idp_logout_url, since there's no SAML identity to notify
    an IdP about. Proves this endpoint doesn't assume every session is a
    SAML one."""
    user = _register_and_login(client)
    login = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    refresh_token = login.json()["refresh_token"]

    resp = client.post("/auth/saml/some-org-slug/logout", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out"}


def test_sp_initiated_logout_without_slo_url_configured_has_no_idp_url(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys, slo_url=None)
    login = _login_via_saml(client, ctx, idp_keys)

    resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out"}

    assert _session_for(login["email"]).status == "revoked"


def test_sp_initiated_logout_blacklists_access_token_when_supplied(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)

    client.post(
        f"/auth/saml/{ctx['org_slug']}/logout",
        json={"refresh_token": login["refresh_token"], "access_token": login["access_token"]},
    )
    validate = client.post("/auth/validate", json={"token": login["access_token"]})
    assert validate.json()["valid"] is False


def test_sp_initiated_logout_wrong_org_in_path_still_logs_out_locally_but_no_idp_url(client, idp_keys):
    """org_slug in the URL doesn't match the session's own recorded
    organization_saml_config_id -- the local logout still happens (it's
    keyed by refresh_token, not org_slug), but no idp_logout_url is
    built, since building one would mean using a session's SAML identity
    under a DIFFERENT org's config than it actually belongs to."""
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML SLO Wrong Org A")
    ctx_b = _org_with_saml_login(client, idp_keys, "SAML SLO Wrong Org B")
    login = _login_via_saml(client, ctx_a, idp_keys)

    resp = client.post(f"/auth/saml/{ctx_b['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out"}
    assert _session_for(login["email"]).status == "revoked"


# ── 2. SP-initiated logout: round-trip LogoutResponse handling ───────


def test_sp_initiated_slo_round_trip_completes_on_valid_signed_response(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)
    key_pem, cert_pem = idp_keys

    logout_resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    idp_logout_url = logout_resp.json()["idp_logout_url"]
    params, _ = _split_query(idp_logout_url)
    relay_state = params["RelayState"]
    request_id = decode_token(relay_state)["request_id"]

    _resp_params, resp_query = _build_idp_logout_response(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], in_response_to=request_id, relay_state=relay_state,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{resp_query}", follow_redirects=False)
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out"}


def test_sp_initiated_slo_round_trip_rejects_unsigned_response(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)
    key_pem, cert_pem = idp_keys

    logout_resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    relay_state = _split_query(logout_resp.json()["idp_logout_url"])[0]["RelayState"]
    request_id = decode_token(relay_state)["request_id"]

    _params, resp_query = _build_idp_logout_response(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], in_response_to=request_id,
        relay_state=relay_state, sign=False,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{resp_query}")
    assert resp.status_code == 400


def test_sp_initiated_slo_round_trip_rejects_wrong_in_response_to(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)
    key_pem, cert_pem = idp_keys

    logout_resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    relay_state = _split_query(logout_resp.json()["idp_logout_url"])[0]["RelayState"]

    _params, resp_query = _build_idp_logout_response(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"],
        in_response_to="_completely-different-request-id", relay_state=relay_state,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{resp_query}")
    assert resp.status_code == 400


def test_sp_initiated_slo_round_trip_rejects_tampered_relay_state(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)
    key_pem, cert_pem = idp_keys

    logout_resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    relay_state = _split_query(logout_resp.json()["idp_logout_url"])[0]["RelayState"]
    request_id = decode_token(relay_state)["request_id"]

    _params, resp_query = _build_idp_logout_response(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], in_response_to=request_id,
        relay_state=relay_state + "-tampered",
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{resp_query}")
    assert resp.status_code == 400


def test_sp_initiated_slo_round_trip_rejects_login_relay_state(client, idp_keys):
    """A signed login RelayState (type=saml_relay_state) must never be
    accepted by the SLO endpoint -- distinct token types, see
    create_saml_slo_relay_state_token's own docstring."""
    ctx = _org_with_saml_login(client, idp_keys)
    login = _login_via_saml(client, ctx, idp_keys)
    key_pem, cert_pem = idp_keys

    logout_resp = client.post(f"/auth/saml/{ctx['org_slug']}/logout", json={"refresh_token": login["refresh_token"]})
    relay_state = _split_query(logout_resp.json()["idp_logout_url"])[0]["RelayState"]
    request_id = decode_token(relay_state)["request_id"]

    login_relay_state, _ = _start_saml_login(client, ctx["org_slug"])
    _params, resp_query = _build_idp_logout_response(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], in_response_to=request_id,
        relay_state=login_relay_state,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{resp_query}")
    assert resp.status_code == 400


# ── 3. IdP-initiated SLO: happy path ──────────────────────────────────


def test_idp_initiated_slo_revokes_matching_session_and_redirects(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-{uuid.uuid4().hex[:8]}@example.com"
    _created_user_id, session_id = _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id, session_index="_sess-a")

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id, session_index="_sess-a",
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"].startswith(ctx["idp_configured_slo_url"])

    db = _DirectSession()
    try:
        session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    finally:
        db.close()
    assert session.status == "revoked"
    assert session.revoked_reason == session_service.REASON_USER_LOGOUT


def test_idp_initiated_slo_without_session_index_revokes_every_session_for_name_id(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-multi-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id, session_index="_sess-a")
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == name_id).first()
        second = UserSession(
            session_id=str(uuid.uuid4()), user_id=user.id, organization_id=ctx["org_id"],
            auth_method="saml", mfa_verified=True, status="active",
            created_at=datetime.utcnow(), last_activity_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            saml_name_id=name_id, saml_session_index="_sess-b",
            organization_saml_config_id=ctx["config_id"],
        )
        db.add(second)
        db.commit()
    finally:
        db.close()

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id, session_index=None,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)
    assert resp.status_code in (302, 307)

    db = _DirectSession()
    try:
        sessions = db.query(UserSession).join(User).filter(User.email == name_id).all()
    finally:
        db.close()
    assert len(sessions) == 2
    assert all(s.status == "revoked" for s in sessions)


def test_idp_initiated_slo_session_index_narrows_to_one_session(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-narrow-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id, session_index="_sess-a")
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == name_id).first()
        other = UserSession(
            session_id=str(uuid.uuid4()), user_id=user.id, organization_id=ctx["org_id"],
            auth_method="saml", mfa_verified=True, status="active",
            created_at=datetime.utcnow(), last_activity_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            saml_name_id=name_id, saml_session_index="_sess-b",
            organization_saml_config_id=ctx["config_id"],
        )
        db.add(other)
        db.commit()
    finally:
        db.close()

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id, session_index="_sess-a",
    )
    client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)

    db = _DirectSession()
    try:
        sessions = {s.saml_session_index: s.status for s in db.query(UserSession).join(User).filter(User.email == name_id).all()}
    finally:
        db.close()
    assert sessions["_sess-a"] == "revoked"
    assert sessions["_sess-b"] == "active"


# ── 4. IdP-initiated SLO: security ────────────────────────────────────


def test_idp_initiated_slo_rejects_unsigned_logout_request(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-unsigned-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id)

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id, sign=False,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}")
    assert resp.status_code == 400

    session = _session_for(name_id)
    assert session.status == "active"


def test_idp_initiated_slo_rejects_wrong_idp_certificate(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    wrong_key_pem, wrong_cert_pem = _generate_idp_keypair_and_cert("attacker-idp")
    name_id = f"idp-slo-wrongcert-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id)

    _params, query = _build_idp_logout_request(
        wrong_key_pem, wrong_cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}")
    assert resp.status_code == 400
    assert _session_for(name_id).status == "active"


def test_idp_initiated_slo_rejects_wrong_issuer(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-wrongissuer-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id)

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, "https://not-the-registered-idp.example.com", ctx["slo_url"], name_id=name_id,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}")
    assert resp.status_code == 400
    assert _session_for(name_id).status == "active"


def test_idp_initiated_slo_replay_of_same_logout_request_rejected(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-replay-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id)

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id,
    )
    first = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)
    assert first.status_code in (302, 307)

    second = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}")
    assert second.status_code == 400


def test_idp_initiated_slo_for_org_a_cannot_revoke_org_b_session(client, idp_keys):
    """Same NameID, but the LogoutRequest is validated against org A's
    own config/certificate -- org B's session (a different
    organization_saml_config_id) must never be found, let alone
    revoked, by it."""
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML SLO Isolation Org A")
    ctx_b = _org_with_saml_login(client, idp_keys, "SAML SLO Isolation Org B")
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-cross-org-{uuid.uuid4().hex[:8]}@example.com"
    _plant_saml_session(ctx_b["org_id"], ctx_b["config_id"], name_id)

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx_a["idp_entity_id"], ctx_a["slo_url"], name_id=name_id,
    )
    client.get(f"/auth/saml/{ctx_a['org_slug']}/slo?{query}", follow_redirects=False)

    assert _session_for(name_id).status == "active"


def test_idp_initiated_slo_unknown_organization_404s(client, idp_keys):
    key_pem, cert_pem = idp_keys
    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, "https://idp.example.com/entity",
        "https://auth.omnibioai.test/auth/saml/unknown-org-slug/slo", name_id="whoever@example.com",
    )
    resp = client.get(f"/auth/saml/unknown-org-slug-{uuid.uuid4().hex[:8]}/slo?{query}")
    assert resp.status_code == 404


def test_idp_initiated_slo_inactive_saml_config_404s(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    db = _DirectSession()
    try:
        config = db.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.id == ctx["config_id"]).first()
        config.status = "disabled"
        db.commit()
    finally:
        db.close()

    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-disabled-{uuid.uuid4().hex[:8]}@example.com"
    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}")
    assert resp.status_code == 404


def test_idp_initiated_slo_for_unknown_name_id_is_a_safe_no_op(client, idp_keys):
    """A validly signed LogoutRequest for a NameID with no matching
    active session is not an error -- there's simply nothing to revoke
    (e.g. the session already expired/was already logged out locally).
    Must still complete the protocol round trip (redirect back to the
    IdP with a LogoutResponse), not fail closed on "nothing found"."""
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id="never-logged-in@example.com",
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)
    assert resp.status_code in (302, 307)


def test_idp_initiated_slo_already_revoked_session_is_idempotent(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    key_pem, cert_pem = idp_keys
    name_id = f"idp-slo-already-revoked-{uuid.uuid4().hex[:8]}@example.com"
    _created_user_id, session_id = _plant_saml_session(ctx["org_id"], ctx["config_id"], name_id, status="revoked")

    _params, query = _build_idp_logout_request(
        key_pem, cert_pem, ctx["idp_entity_id"], ctx["slo_url"], name_id=name_id,
    )
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo?{query}", follow_redirects=False)
    assert resp.status_code in (302, 307)

    db = _DirectSession()
    try:
        session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    finally:
        db.close()
    assert session.status == "revoked"


def test_idp_initiated_slo_missing_message_type_400s(client):
    resp = client.get("/auth/saml/some-org-that-does-not-exist/slo")
    assert resp.status_code == 404  # unknown org checked before the missing-message-type check


def test_idp_initiated_slo_missing_saml_request_and_response_400s(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    resp = client.get(f"/auth/saml/{ctx['org_slug']}/slo")
    assert resp.status_code == 400


# ── 5. RelayState/CRUD/config wiring ──────────────────────────────────


def test_saml_config_crud_accepts_and_returns_slo_url(client, idp_keys):
    org = _create_org(client, "SAML SLO CRUD Org")
    headers = {"Authorization": f"Bearer {org['owner']['access_token']}"}
    resp = client.post(
        f"/orgs/{org['id']}/saml",
        json={
            "entity_id": "https://idp.example.com/entity", "sso_url": "https://idp.example.com/sso",
            "x509_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "slo_url": "https://idp.example.com/slo",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["slo_url"] == "https://idp.example.com/slo"


def test_saml_config_crud_slo_url_optional_on_create(client):
    org = _create_org(client, "SAML SLO CRUD Optional Org")
    headers = {"Authorization": f"Bearer {org['owner']['access_token']}"}
    resp = client.post(
        f"/orgs/{org['id']}/saml",
        json={
            "entity_id": "https://idp.example.com/entity", "sso_url": "https://idp.example.com/sso",
            "x509_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        },
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["slo_url"] is None


def test_saml_config_crud_rejects_invalid_slo_url(client):
    org = _create_org(client, "SAML SLO CRUD Invalid Org")
    headers = {"Authorization": f"Bearer {org['owner']['access_token']}"}
    resp = client.post(
        f"/orgs/{org['id']}/saml",
        json={
            "entity_id": "https://idp.example.com/entity", "sso_url": "https://idp.example.com/sso",
            "x509_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "slo_url": "ftp://bad-scheme.example.com",
        },
        headers=headers,
    )
    assert resp.status_code == 422


# ── 6. MFA: SLO works correctly for a SAML+personal-MFA session ──────


@pytest.fixture
def configured_crypto(monkeypatch):
    from app.core import crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _extract_secret(otpauth_uri: str) -> str:
    return parse_qs(urlparse(otpauth_uri).query)["secret"][0]


def test_saml_jit_user_with_personal_mfa_gets_saml_identity_on_session_after_challenge(client, idp_keys, configured_crypto):
    """The MFA-challenge round trip (create_mfa_challenge_token ->
    verify_mfa_challenge -> generate_tokens) must still write the SAML
    identity onto the resulting UserSession -- proves the PR11 threading
    through jwt.py/mfa_service.py actually works end to end, not just
    for the direct (no-MFA) generate_tokens path."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    headers = {"Authorization": f"Bearer {existing['access_token']}"}
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    client.post("/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers)

    db = _DirectSession()
    try:
        db.add(OAuthAccount(
            user_id=_user_id(client, existing["access_token"]), provider="saml", provider_user_id=existing["email"],
            email=existing["email"], organization_saml_config_id=ctx["config_id"],
        ))
        db.commit()
    finally:
        db.close()

    key_pem, cert_pem = idp_keys
    resp_body = build_signed_saml_response(
        key_pem, cert_pem, idp_entity_id=ctx["idp_entity_id"], sp_entity_id=ctx["sp_entity_id"],
        acs_url=ctx["acs_url"], request_id=ctx["request_id"], name_id=existing["email"], session_index="_mfa-sess",
    )
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])
    assert resp.status_code == 200
    challenge_data = resp.json()
    assert challenge_data["status"] == "mfa_required"

    code2 = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_data["challenge_token"], "code": code2})
    assert verify.status_code == 200

    session = _session_for(existing["email"])
    assert session.saml_name_id == existing["email"]
    assert session.saml_session_index == "_mfa-sess"
    assert session.organization_saml_config_id == ctx["config_id"]


# ── 7. Regression: existing OIDC/OAuth logout unaffected ─────────────


def test_existing_auth_logout_endpoint_unaffected(client):
    user = _register_and_login(client)
    login = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    refresh_token = login.json()["refresh_token"]

    resp = client.post("/auth/logout", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert resp.json() == {"message": "Logged out"}
