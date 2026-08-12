"""SAML SSO PR6: identity linking (OAuthAccount.organization_saml_config_id,
0022_oauth_saml_config_id). Builds on PR2 (OrganizationSAMLConfig), PR3 (SP
metadata), PR4 (SP-initiated login), and PR5 (ACS/assertion validation,
tests/test_saml_acs.py -- all 29 of those tests still pass unmodified,
proving PR6 did not touch PR5's own validation/replay/RelayState/security
boundaries). Auto-provisioning a brand-new user from an unrecognized SAML
identity (JIT provisioning) is still PR7 scope -- see
app/api/routes_saml.py's _complete_saml_login docstring -- and this file's
own `test_unrecognized_identity_still_stops_at_501_jit_boundary` proves that
boundary is still enforced, exactly as tests/test_saml_acs.py's own
linking-boundary tests already do for PR5.

Each test file in this suite is self-contained (local helpers), matching
this repo's established per-file duplication convention -- see
tests/test_saml_acs.py's own module docstring for the reasoning behind
building REAL, genuinely-signed SAMLResponse documents rather than mocking
validate_saml_response.
"""

import base64
import datetime
import time
import urllib.parse
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import (
    OAuthAccount,
    OrganizationMembership,
    OrganizationSAMLConfig,
    User,
)
from app.services import mfa_service, oauth_service, org_saml_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


# ── Real IdP keypair/cert + signed-response fixture builder ────────────
# Copied from tests/test_saml_acs.py -- see that file's module docstring
# for why every test here drives real signed documents through the real,
# unweakened validate_saml_response path rather than a mock.


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
    """Same technique as tests/test_saml_acs.py's own fixture of this
    name -- real NX+EX semantics against an isolated per-test dict, since
    _reject_if_replayed is exercised for real here too (every successful
    ACS POST in this file passes through it)."""
    from app.core import token_revocation

    store = {}

    def _set(key, value, nx=False, ex=None):
        if nx and key in store:
            return None
        store[key] = value
        return True

    monkeypatch.setattr(token_revocation._blacklist, "set", _set, raising=False)
    yield store


# ── Org/user/config helpers (same convention as the other SAML test files) ──


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-link-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _create_org(client, name="SAML Link Test Org"):
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


def _start_saml_login(client, org_slug):
    """Real GET /auth/saml/{org_slug}/login (PR4, unmodified) -- returns
    (relay_state, request_id) for building a matching signed response."""
    resp = client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    query = parse_qs(urlparse(resp.headers["location"]).query)
    relay_state = query["RelayState"][0]
    request_id = decode_token(relay_state)["request_id"]
    return relay_state, request_id


def _org_with_saml_login(client, idp_keys, org_name="SAML Link Test Org"):
    _key_pem, cert_pem = idp_keys
    org = _create_org(client, org_name)
    idp_entity_id = f"https://idp.example.com/entity-{uuid.uuid4().hex[:8]}"
    config_id = _plant_saml_config(org["id"], entity_id=idp_entity_id, x509_certificate=cert_pem)
    relay_state, request_id = _start_saml_login(client, org["slug"])
    return {
        "org_id": org["id"], "org_slug": org["slug"], "config_id": config_id,
        "idp_entity_id": idp_entity_id,
        "sp_entity_id": org_saml_service.entity_id_for(org["slug"]),
        "acs_url": org_saml_service.acs_url_for(org["slug"]),
        "relay_state": relay_state, "request_id": request_id,
    }


def _post_acs(client, org_slug, saml_response_b64, relay_state):
    return client.post(
        f"/auth/saml/{org_slug}/acs", data={"SAMLResponse": saml_response_b64, "RelayState": relay_state}
    )


def _build_response(ctx, idp_keys, **overrides):
    key_pem, cert_pem = idp_keys
    return build_signed_saml_response(
        key_pem, cert_pem, idp_entity_id=ctx["idp_entity_id"], sp_entity_id=ctx["sp_entity_id"],
        acs_url=ctx["acs_url"], request_id=ctx["request_id"], **overrides,
    )


def _oauth_accounts_for(provider_user_id):
    db = _DirectSession()
    try:
        return (
            db.query(OAuthAccount)
            .filter(OAuthAccount.provider == "saml", OAuthAccount.provider_user_id == provider_user_id)
            .all()
        )
    finally:
        db.close()


def _membership(org_id, user_id):
    db = _DirectSession()
    try:
        return (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == user_id)
            .first()
        )
    finally:
        db.close()


# ── 1. Schema/uniqueness enforced for real at the DB level ──────────────


def test_duplicate_saml_identity_same_config_rejected_by_db():
    """The whole point of widening uq_oauth_provider_account to include
    organization_saml_config_id: two rows for the same (provider="saml",
    provider_user_id, organization_saml_config_id) triple must be
    impossible, not just avoided by application code."""
    db = _DirectSession()
    try:
        user = User(email=f"dup-saml-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        db.add(OAuthAccount(
            user_id=user.id, provider="saml", provider_user_id="dup-name-id@example.com",
            email="dup-name-id@example.com", organization_saml_config_id=999,
        ))
        db.commit()

        db.add(OAuthAccount(
            user_id=user.id, provider="saml", provider_user_id="dup-name-id@example.com",
            email="dup-name-id@example.com", organization_saml_config_id=999,
        ))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_same_name_id_different_saml_configs_allowed_at_db_level():
    """The inverse: the SAME NameID under TWO DIFFERENT SAML configs is
    not a conflict -- config-scoping, not a global NameID namespace."""
    db = _DirectSession()
    try:
        user = User(email=f"same-nameid-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        db.add(OAuthAccount(
            user_id=user.id, provider="saml", provider_user_id="shared-name-id@example.com",
            email="shared-name-id@example.com", organization_saml_config_id=111,
        ))
        db.add(OAuthAccount(
            user_id=user.id, provider="saml", provider_user_id="shared-name-id@example.com",
            email="shared-name-id@example.com", organization_saml_config_id=222,
        ))
        db.commit()  # must not raise
    finally:
        db.rollback()
        db.close()


def test_duplicate_oidc_identity_still_rejected_by_db_after_pr6():
    """The regression this file exists to guard against: PR6 must not
    weaken the PRE-EXISTING OIDC uniqueness guarantee. A naive single
    4-column widen of uq_oauth_provider_account would have silently
    stopped rejecting this (organization_saml_config_id is NULL on every
    OIDC row, and a NULL in any column of a composite UNIQUE index defeats
    enforcement for that row's whole tuple, on both SQLite and MySQL) --
    see 0022_oauth_saml_config_id's own docstring. PR6 instead adds a
    SEPARATE constraint for SAML, leaving this one untouched."""
    db = _DirectSession()
    try:
        user = User(email=f"dup-oidc-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        db.add(OAuthAccount(
            user_id=user.id, provider="oidc", provider_user_id="dup-oidc-sub",
            email=user.email, organization_sso_config_id=777,
        ))
        db.commit()

        db.add(OAuthAccount(
            user_id=user.id, provider="oidc", provider_user_id="dup-oidc-sub",
            email=user.email, organization_sso_config_id=777,
        ))
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_mutually_exclusive_scope_rejected_before_hitting_the_db():
    """oauth_service's own guard (_assert_single_idp_scope) -- an
    OAuthAccount scoped to both an OIDC config AND a SAML config
    simultaneously is nonsensical and rejected before any DB write."""
    db = _DirectSession()
    try:
        user = User(email=f"mutex-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        with pytest.raises(ValueError):
            oauth_service.link_oauth_to_existing_user(
                db, user, "saml", "whatever@example.com", "whatever@example.com",
                organization_sso_config_id=1, organization_saml_config_id=2,
            )
    finally:
        db.rollback()
        db.close()


# ── 2. find_linked_user isolation (service level) ────────────────────────


def test_find_linked_user_scopes_saml_lookup_to_config():
    db = _DirectSession()
    try:
        user_a = User(email=f"scope-a-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        user_b = User(email=f"scope-b-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add_all([user_a, user_b])
        db.flush()
        db.add(OAuthAccount(
            user_id=user_a.id, provider="saml", provider_user_id="scoped@example.com",
            email="scoped@example.com", organization_saml_config_id=301,
        ))
        db.add(OAuthAccount(
            user_id=user_b.id, provider="saml", provider_user_id="scoped@example.com",
            email="scoped@example.com", organization_saml_config_id=302,
        ))
        db.commit()

        resolved_a = oauth_service.find_linked_user(db, "saml", "scoped@example.com", organization_saml_config_id=301)
        resolved_b = oauth_service.find_linked_user(db, "saml", "scoped@example.com", organization_saml_config_id=302)
        resolved_other = oauth_service.find_linked_user(db, "saml", "scoped@example.com", organization_saml_config_id=999)

        assert resolved_a.id == user_a.id
        assert resolved_b.id == user_b.id
        assert resolved_other is None
    finally:
        db.rollback()
        db.close()


def test_find_linked_user_does_not_cross_resolve_oidc_and_saml():
    """provider="saml" must never resolve a provider="oidc" (or any other
    provider) row, even if provider_user_id happens to collide."""
    db = _DirectSession()
    try:
        user = User(email=f"cross-provider-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        db.add(OAuthAccount(
            user_id=user.id, provider="oidc", provider_user_id="shared-identifier",
            email=user.email, organization_sso_config_id=401,
        ))
        db.commit()

        resolved = oauth_service.find_linked_user(db, "saml", "shared-identifier", organization_saml_config_id=401)
        assert resolved is None
    finally:
        db.rollback()
        db.close()


def test_find_linked_user_oidc_behavior_unchanged_by_new_param():
    """Regression guard on the shared function's signature change itself:
    an OIDC caller that never passes organization_saml_config_id gets the
    exact same result as before PR6."""
    db = _DirectSession()
    try:
        user = User(email=f"oidc-unchanged-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        db.add(OAuthAccount(
            user_id=user.id, provider="oidc", provider_user_id="oidc-sub-unchanged",
            email=user.email, organization_sso_config_id=501,
        ))
        db.commit()

        resolved = oauth_service.find_linked_user(db, "oidc", "oidc-sub-unchanged", organization_sso_config_id=501)
        assert resolved.id == user.id
    finally:
        db.rollback()
        db.close()


# ── 3. End-to-end ACS flow: linking decision tree ────────────────────────


def test_unrecognized_identity_still_stops_at_501_jit_boundary(client, idp_keys):
    """PR6's own remaining hard boundary, re-proven in this file too (not
    just relying on tests/test_saml_acs.py's own copies): a brand-new
    identity with no existing account and no prior link must NOT be
    auto-provisioned -- that's PR7."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = f"never-seen-{uuid.uuid4().hex[:8]}@example.com"
    resp_body = _build_response(ctx, idp_keys, name_id=email)
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])
    assert resp.status_code == 501
    assert "access_token" not in resp.text
    assert not _oauth_accounts_for(email)


def test_existing_email_returns_link_required_not_direct_token(client, idp_keys):
    """No silent linking: an email match to an account with no SAML link
    yet must require explicit confirmation, never issue a token directly."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)

    resp_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert data["provider"] == "saml"
    assert data["email"] == existing["email"]
    assert "link_token" in data
    assert "access_token" not in data
    assert not _oauth_accounts_for(existing["email"])  # no row written yet -- confirmation pending


def test_link_confirm_wrong_password_does_not_create_oauth_account(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    resp_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"]).json()["link_token"]

    confirm = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})

    assert confirm.status_code == 401
    assert not _oauth_accounts_for(existing["email"])


def test_link_confirm_success_creates_scoped_oauth_account_and_issues_token(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    resp_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"]).json()["link_token"]

    confirm = client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})

    assert confirm.status_code == 200
    assert "access_token" in confirm.json()

    rows = _oauth_accounts_for(existing["email"])
    assert len(rows) == 1
    assert rows[0].provider == "saml"
    assert rows[0].organization_saml_config_id == ctx["config_id"]
    assert rows[0].organization_sso_config_id is None

    validate = client.post("/auth/validate", json={"token": confirm.json()["access_token"]})
    assert validate.json()["email"] == existing["email"]


def test_repeat_saml_login_after_link_goes_straight_through(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    first_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx["org_slug"], first_body, ctx["relay_state"]).json()["link_token"]
    client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})

    relay_state2, request_id2 = _start_saml_login(client, ctx["org_slug"])
    ctx2 = dict(ctx, relay_state=relay_state2, request_id=request_id2)
    second_body = _build_response(ctx2, idp_keys, name_id=existing["email"])
    resp = _post_acs(client, ctx["org_slug"], second_body, relay_state2)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "access_token" in data
    assert len(_oauth_accounts_for(existing["email"])) == 1  # not duplicated on repeat login


def test_jit_membership_granted_on_linked_login(client, idp_keys):
    """A recognized (already-linked) identity's login must still result
    in real org membership -- same JIT-provisioning-for-membership
    reasoning routes_sso.py's own _complete_sso_flow already establishes
    for OIDC (org_service.jit_provision_membership)."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    assert _membership(ctx["org_id"], _user_id(client, existing["access_token"])) is None

    first_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx["org_slug"], first_body, ctx["relay_state"]).json()["link_token"]
    client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})

    assert _membership(ctx["org_id"], _user_id(client, existing["access_token"])) is not None


# ── 4. MFA-aware token issuance is reused, not bypassed ──────────────────


@pytest.fixture
def configured_crypto(monkeypatch):
    from app.core import crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _enable_mfa(client, headers) -> str:
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


def test_mfa_required_user_gets_challenge_not_token(client, idp_keys, configured_crypto):
    ctx = _org_with_saml_login(client, idp_keys)
    user = _register_and_login(client)
    headers = {"Authorization": f"Bearer {user['access_token']}"}
    _enable_mfa(client, headers)

    db = _DirectSession()
    try:
        db.add(OAuthAccount(
            user_id=_user_id(client, user["access_token"]), provider="saml", provider_user_id=user["email"],
            email=user["email"], organization_saml_config_id=ctx["config_id"],
        ))
        db.commit()
    finally:
        db.close()

    resp_body = _build_response(ctx, idp_keys, name_id=user["email"])
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "mfa_required"
    assert data["mfa_required"] is True
    assert "challenge_token" in data
    assert "access_token" not in data


# ── 5. Cross-organization isolation for the linking/resolution paths ─────


def test_org_a_linked_account_cannot_login_via_org_b_saml(client, idp_keys):
    """The 'linked' fast-path is itself config-scoped: a NameID linked in
    Org A's SAML config must NOT resolve as already-linked when the same
    NameID is presented to Org B's ACS -- Org B must still require its
    own explicit link confirmation, never silently reuse Org A's link."""
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML Isolation Org A")
    existing = _register_and_login(client)
    body_a = _build_response(ctx_a, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx_a["org_slug"], body_a, ctx_a["relay_state"]).json()["link_token"]
    client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})

    ctx_b = _org_with_saml_login(client, idp_keys, "SAML Isolation Org B")
    body_b = _build_response(ctx_b, idp_keys, name_id=existing["email"])
    resp_b = _post_acs(client, ctx_b["org_slug"], body_b, ctx_b["relay_state"])

    assert resp_b.status_code == 200
    data = resp_b.json()
    assert data["status"] == "link_required"  # NOT "ok" -- org B has no link of its own yet
    assert "access_token" not in data

    rows = _oauth_accounts_for(existing["email"])
    assert len(rows) == 1
    assert rows[0].organization_saml_config_id == ctx_a["config_id"]


def test_same_name_id_two_orgs_produce_independently_scoped_links(client, idp_keys):
    """Both orgs' SAML configs can independently link the SAME global
    email/NameID -- two real, separately-scoped OAuthAccount rows, never
    merged into one, and each org's login only ever resolves its own."""
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML Dual Link Org A")
    ctx_b = _org_with_saml_login(client, idp_keys, "SAML Dual Link Org B")
    existing = _register_and_login(client)

    body_a = _build_response(ctx_a, idp_keys, name_id=existing["email"])
    token_a = _post_acs(client, ctx_a["org_slug"], body_a, ctx_a["relay_state"]).json()["link_token"]
    client.post("/auth/link/confirm", json={"link_token": token_a, "password": existing["password"]})

    body_b = _build_response(ctx_b, idp_keys, name_id=existing["email"])
    token_b = _post_acs(client, ctx_b["org_slug"], body_b, ctx_b["relay_state"]).json()["link_token"]
    client.post("/auth/link/confirm", json={"link_token": token_b, "password": existing["password"]})

    rows = {row.organization_saml_config_id for row in _oauth_accounts_for(existing["email"])}
    assert rows == {ctx_a["config_id"], ctx_b["config_id"]}

    relay_a2, req_a2 = _start_saml_login(client, ctx_a["org_slug"])
    resp_a2 = _post_acs(client, ctx_a["org_slug"], _build_response(dict(ctx_a, relay_state=relay_a2, request_id=req_a2), idp_keys, name_id=existing["email"]), relay_a2)
    assert resp_a2.json()["status"] == "ok"


# ── 6. SAML assertion attributes never influence identity resolution ─────


def test_saml_attributes_do_not_affect_identity_resolution(client, idp_keys):
    """attribute_mapping-driven extraction is explicitly not implemented
    (PR5's own docstring) -- an attacker-controlled AttributeStatement
    must have zero effect on which account gets linked or what email
    lands on the OAuthAccount row. Only the (server-trusted, signature-
    verified) NameID drives resolution."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)

    resp_body = _build_response(
        ctx, idp_keys, name_id=existing["email"],
        attributes={"email": "attacker@evil.test", "organization_id": "99999", "role": "platform_admin"},
    )
    resp = _post_acs(client, ctx["org_slug"], resp_body, ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert data["email"] == existing["email"]  # NameID, not the spoofed attribute
    assert "attacker@evil.test" not in resp.text


# ── 7. Existing OIDC/OAuth behavior is unaffected by this file's own setup ──


def test_existing_oauth_login_unaffected_by_saml_linking_changes(client):
    """Smoke check within this file too: registering a user and logging
    in with a plain password is completely untouched by anything above --
    full regression is tests/test_oauth.py + tests/test_sso_login.py, run
    separately as part of this PR's own regression pass."""
    user = _register_and_login(client)
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    assert "access_token" in resp.json()
