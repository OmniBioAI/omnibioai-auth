"""SAML SSO PR7: JIT provisioning of a brand-new User from a fully
validated, never-before-seen SAML identity. Builds on PR5 (ACS/assertion
validation, tests/test_saml_acs.py) and PR6 (identity linking,
tests/test_saml_identity_linking.py) -- PR7 only replaces the remaining
501 stop those two files' own boundary tests used to assert (see both
files' updated tests/comments) with real provisioning for case C of
app/api/routes_saml.py's _complete_saml_login docstring: no existing
link AND no existing user with that email.

Reuses oauth_service.create_user_with_oauth + org_service.
jit_provision_membership + auth_service.generate_tokens_or_mfa_challenge
-- the exact same provider-agnostic choke points OIDC's own new-user
branch (routes_sso.py::_complete_sso_flow) already uses -- so this file
only tests the SAML-specific wiring (NameID validation, RelayState-
resolved organization/config scoping, and the IntegrityError-retry loop
_complete_saml_login adds around create_user_with_oauth), not those
helpers' own internals a second time.

Same convention as the other SAML test files: local, self-contained
helpers building REAL, genuinely-signed SAMLResponse documents through
the real, unweakened validate_saml_response path -- see
tests/test_saml_acs.py's own module docstring for why.
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
    OrganizationMFAPolicy,
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


# ── Org/user/config helpers (same convention as the other SAML test files) ──


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"saml-jit-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _create_org(client, name="SAML JIT Test Org"):
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
    resp = client.get(f"/auth/saml/{org_slug}/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    query = parse_qs(urlparse(resp.headers["location"]).query)
    relay_state = query["RelayState"][0]
    request_id = decode_token(relay_state)["request_id"]
    return relay_state, request_id


def _org_with_saml_login(client, idp_keys, org_name="SAML JIT Test Org"):
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


def _user_by_email(email):
    db = _DirectSession()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


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


def _new_email():
    return f"jit-new-{uuid.uuid4().hex[:8]}@example.com"


# ── A. Brand-new user ─────────────────────────────────────────────────


def test_new_identity_creates_user_oauthaccount_and_membership(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()

    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "access_token" in data
    assert "refresh_token" in data

    user = _user_by_email(email)
    assert user is not None
    assert user.status == "active"
    assert user.hashed_password is None

    rows = _oauth_accounts_for(email)
    assert len(rows) == 1
    assert rows[0].provider == "saml"
    assert rows[0].provider_user_id == email
    assert rows[0].user_id == user.id
    assert rows[0].organization_saml_config_id == ctx["config_id"]
    assert rows[0].organization_sso_config_id is None

    membership = _membership(ctx["org_id"], user.id)
    assert membership is not None
    assert membership.status == "active"

    validate = client.post("/auth/validate", json={"token": data["access_token"]})
    assert validate.json()["email"] == email


def test_new_identity_default_membership_role_is_org_member(client, idp_keys):
    """PR7 must not invent SAML-specific roles -- same default
    (org_member, no permissions) org_service.jit_provision_membership
    already grants OIDC's new-user branch."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()
    _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    user = _user_by_email(email)
    db = _DirectSession()
    try:
        membership = (
            db.query(OrganizationMembership)
            .filter(OrganizationMembership.organization_id == ctx["org_id"], OrganizationMembership.user_id == user.id)
            .first()
        )
        role_names = {role.name for role in membership.roles}
    finally:
        db.close()
    assert role_names == {"org_member"}


def test_repeat_login_after_jit_does_not_duplicate_anything(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()
    first = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])
    assert first.status_code == 200

    relay_state2, request_id2 = _start_saml_login(client, ctx["org_slug"])
    ctx2 = dict(ctx, relay_state=relay_state2, request_id=request_id2)
    second = _post_acs(client, ctx["org_slug"], _build_response(ctx2, idp_keys, name_id=email), relay_state2)

    assert second.status_code == 200
    assert second.json()["status"] == "ok"
    assert len(_oauth_accounts_for(email)) == 1

    user = _user_by_email(email)
    assert (
        _DirectSession().query(User).filter(User.email == email).count() == 1
    )
    assert _membership(ctx["org_id"], user.id) is not None


# ── B. Existing-linked identity (PR6 regression) ─────────────────────────


def test_existing_linked_identity_still_logs_in_directly(client, idp_keys):
    """An already-linked identity (created via PR6's own explicit
    password-confirmation flow) must still hit the fast path -- PR7 adds
    a third branch, it does not touch the first two."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    first_body = _build_response(ctx, idp_keys, name_id=existing["email"])
    link_token = _post_acs(client, ctx["org_slug"], first_body, ctx["relay_state"]).json()["link_token"]
    confirm = client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})
    assert confirm.status_code == 200

    relay_state2, request_id2 = _start_saml_login(client, ctx["org_slug"])
    ctx2 = dict(ctx, relay_state=relay_state2, request_id=request_id2)
    second_body = _build_response(ctx2, idp_keys, name_id=existing["email"])
    resp = _post_acs(client, ctx["org_slug"], second_body, relay_state2)

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert len(_oauth_accounts_for(existing["email"])) == 1
    assert _DirectSession().query(User).filter(User.email == existing["email"]).count() == 1


# ── C. Email collision (PR6 regression) ───────────────────────────────


def test_existing_email_still_requires_confirmation_not_jit(client, idp_keys):
    """The single most important PR7 regression: an identity matching an
    EXISTING user's email must never be silently JIT-provisioned or
    silently linked -- it must still hit PR6's link_required/explicit-
    password-confirmation path, exactly as before PR7 existed."""
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)

    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=existing["email"]), ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "link_required"
    assert "access_token" not in data
    assert not _oauth_accounts_for(existing["email"])
    assert _DirectSession().query(User).filter(User.email == existing["email"]).count() == 1


def test_email_collision_wrong_password_does_not_link_or_provision(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    link_token = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=existing["email"]), ctx["relay_state"]).json()["link_token"]

    confirm = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})

    assert confirm.status_code == 401
    assert not _oauth_accounts_for(existing["email"])


def test_email_collision_correct_confirmation_links_safely(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    existing = _register_and_login(client)
    link_token = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=existing["email"]), ctx["relay_state"]).json()["link_token"]

    confirm = client.post("/auth/link/confirm", json={"link_token": link_token, "password": existing["password"]})

    assert confirm.status_code == 200
    assert "access_token" in confirm.json()
    rows = _oauth_accounts_for(existing["email"])
    assert len(rows) == 1
    assert rows[0].organization_saml_config_id == ctx["config_id"]


# ── D. Organization isolation ─────────────────────────────────────────


def test_jit_membership_scoped_to_originating_org_only(client, idp_keys):
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML JIT Isolation Org A")
    ctx_b = _org_with_saml_login(client, idp_keys, "SAML JIT Isolation Org B")
    email = _new_email()

    resp = _post_acs(client, ctx_a["org_slug"], _build_response(ctx_a, idp_keys, name_id=email), ctx_a["relay_state"])
    assert resp.status_code == 200

    user = _user_by_email(email)
    assert _membership(ctx_a["org_id"], user.id) is not None
    assert _membership(ctx_b["org_id"], user.id) is None


def test_same_email_different_orgs_second_org_requires_confirmation_not_jit(client, idp_keys):
    """A user JIT-provisioned via Org A's SAML is, from Org B's
    perspective, just another existing user -- Org B's own SAML login for
    the same email must fall into PR6's link_required path, never a
    second silent JIT provision and never a silent cross-org link."""
    ctx_a = _org_with_saml_login(client, idp_keys, "SAML JIT Cross Org A")
    ctx_b = _org_with_saml_login(client, idp_keys, "SAML JIT Cross Org B")
    email = _new_email()

    resp_a = _post_acs(client, ctx_a["org_slug"], _build_response(ctx_a, idp_keys, name_id=email), ctx_a["relay_state"])
    assert resp_a.status_code == 200
    assert resp_a.json()["status"] == "ok"

    resp_b = _post_acs(client, ctx_b["org_slug"], _build_response(ctx_b, idp_keys, name_id=email), ctx_b["relay_state"])
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["status"] == "link_required"
    assert "access_token" not in data_b

    assert _DirectSession().query(User).filter(User.email == email).count() == 1
    rows = _oauth_accounts_for(email)
    assert len(rows) == 1
    assert rows[0].organization_saml_config_id == ctx_a["config_id"]


def test_saml_config_from_another_organization_cannot_provision(client, idp_keys):
    """A genuinely valid response for Org A (correctly signed, correctly
    bound, brand-new identity) must be rejected outright -- not
    provisioned into Org B -- when replayed against Org B's ACS
    endpoint, even carrying Org A's own validly-signed RelayState. The
    org-consistency check in _verify_saml_relay_state rejects this before
    the SAMLResponse (and therefore any provisioning decision) is even
    reached."""
    org_a = _create_org(client, "SAML JIT Cross-Config Org A")
    key_a, cert_a = idp_keys
    idp_a = "https://idp-a.example.com/entity"
    _plant_saml_config(org_a["id"], entity_id=idp_a, sso_url="https://idp-a.example.com/sso", x509_certificate=cert_a)

    org_b = _create_org(client, "SAML JIT Cross-Config Org B")
    _key_b, cert_b = _generate_idp_keypair_and_cert("idp-b")
    idp_b = "https://idp-b.example.com/entity"
    _plant_saml_config(org_b["id"], entity_id=idp_b, sso_url="https://idp-b.example.com/sso", x509_certificate=cert_b)

    relay_a, request_id_a = _start_saml_login(client, org_a["slug"])
    email = _new_email()
    resp_body_a = build_signed_saml_response(
        key_a, cert_a, idp_entity_id=idp_a,
        sp_entity_id=org_saml_service.entity_id_for(org_a["slug"]),
        acs_url=org_saml_service.acs_url_for(org_a["slug"]), request_id=request_id_a,
        name_id=email,
    )

    resp = _post_acs(client, org_b["slug"], resp_body_a, relay_a)
    assert resp.status_code == 400
    assert not _oauth_accounts_for(email)
    assert _user_by_email(email) is None

    # Org A's own real flow still works -- proves the 400 above is
    # genuine isolation, not a broken fixture.
    resp_own = _post_acs(client, org_a["slug"], resp_body_a, relay_a)
    assert resp_own.status_code == 200
    assert "access_token" in resp_own.json()


def test_inactive_saml_config_cannot_provision(client, idp_keys):
    """A config deactivated between /login and /acs (the realistic
    "admin turned off SAML mid-flight" case) must reject the callback
    outright -- never provision a user from it."""
    ctx = _org_with_saml_login(client, idp_keys)
    db = _DirectSession()
    try:
        config = db.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.id == ctx["config_id"]).first()
        config.status = "inactive"
        db.commit()
    finally:
        db.close()

    email = _new_email()
    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    assert resp.status_code == 400
    assert not _oauth_accounts_for(email)
    assert _user_by_email(email) is None


# ── E. Attribute handling / trust model ───────────────────────────────


def test_name_id_without_at_sign_rejected_not_provisioned(client, idp_keys):
    ctx = _org_with_saml_login(client, idp_keys)
    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id="not-an-email"), ctx["relay_state"])

    assert resp.status_code == 400
    assert not _oauth_accounts_for("not-an-email")
    assert _DirectSession().query(User).filter(User.email == "not-an-email").count() == 0


def test_untrusted_attributes_cannot_drive_provisioning(client, idp_keys):
    """attribute_mapping-driven extraction is not implemented -- a
    spoofed AttributeStatement must have zero effect on the provisioned
    user's email or on which organization/config resolves the request.
    Only the signature-verified NameID drives provisioning."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()

    resp = _post_acs(
        client, ctx["org_slug"],
        _build_response(
            ctx, idp_keys, name_id=email,
            attributes={"email": "attacker@evil.test", "organization_id": "99999", "role": "platform_admin"},
        ),
        ctx["relay_state"],
    )

    assert resp.status_code == 200
    assert "attacker@evil.test" not in resp.text

    user = _user_by_email(email)
    assert user is not None
    assert _user_by_email("attacker@evil.test") is None
    rows = _oauth_accounts_for(email)
    assert rows[0].email == email


# ── F. Duplicates / races ─────────────────────────────────────────────


def test_concurrent_saml_provisioning_race_resolves_to_single_user(client, idp_keys, monkeypatch):
    """Simulates two requests racing to JIT-provision the SAME NameID
    under the SAME config: a competing OAuthAccount+User is committed by
    a separate session mid-call (standing in for a genuinely concurrent
    second request), and the real create_user_with_oauth's own UNIQUE
    constraint (uq_oauth_provider_saml_account) raises IntegrityError,
    exactly as it would under true concurrency. _complete_saml_login's
    retry loop must resolve to the winner's row, not a 500 and not a
    second user."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()

    real_create = oauth_service.create_user_with_oauth
    winner = {}

    def _racing_create(db, provider, provider_user_id, email_arg, **kwargs):
        winner_db = _DirectSession()
        try:
            winner_user = User(email=email_arg, hashed_password=None, status="active")
            winner_db.add(winner_user)
            winner_db.flush()
            winner_db.add(OAuthAccount(
                user_id=winner_user.id, provider=provider, provider_user_id=provider_user_id,
                email=email_arg, organization_saml_config_id=kwargs.get("organization_saml_config_id"),
            ))
            winner_db.commit()
            winner["user_id"] = winner_user.id
        finally:
            winner_db.close()
        raise IntegrityError("simulated concurrent winner", params=None, orig=Exception("unique violation"))

    monkeypatch.setattr(oauth_service, "create_user_with_oauth", _racing_create)

    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    monkeypatch.setattr(oauth_service, "create_user_with_oauth", real_create)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "access_token" in data

    assert _DirectSession().query(User).filter(User.email == email).count() == 1
    rows = _oauth_accounts_for(email)
    assert len(rows) == 1
    assert rows[0].user_id == winner["user_id"]

    # loser correctly logged in as the winner's own membership, not a
    # second, orphaned membership
    membership = _membership(ctx["org_id"], winner["user_id"])
    assert membership is not None


def test_second_consecutive_integrity_error_fails_closed_not_looping(client, idp_keys, monkeypatch):
    """Bounded retry: if create_user_with_oauth keeps raising
    IntegrityError even after the decision tree is re-run (not a
    recognized, resolvable race), _complete_saml_login must fail closed
    with a 500 rather than looping or eventually provisioning anyway."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()

    def _always_raises(db, *args, **kwargs):
        raise IntegrityError("simulated unresolvable race", params=None, orig=Exception("unique violation"))

    monkeypatch.setattr(oauth_service, "create_user_with_oauth", _always_raises)

    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    assert resp.status_code == 500
    assert _user_by_email(email) is None


def test_duplicate_email_race_never_creates_two_users(client, idp_keys):
    """The non-SAML-specific half of the race story: create_user_with_
    oauth's own DB-level uniqueness (User.email UNIQUE) is what actually
    prevents two users for the same email, regardless of caller. Direct
    service-level proof, matching this repo's existing precedent (see
    tests/test_saml_identity_linking.py's own DB-level uniqueness
    tests)."""
    db = _DirectSession()
    try:
        email = _new_email()
        oauth_service.create_user_with_oauth(db, "saml", email, email, organization_saml_config_id=12345)
        with pytest.raises(IntegrityError):
            oauth_service.create_user_with_oauth(db, "saml", email, email, organization_saml_config_id=67890)
    finally:
        db.rollback()
        db.close()


# ── G. Transactionality ───────────────────────────────────────────────


def test_membership_provisioning_failure_prevents_token_issuance(client, idp_keys, monkeypatch):
    """If org_service.jit_provision_membership fails after the User/
    OAuthAccount were already committed (the same two-step shape OIDC's
    own new-user branch already has -- create_user_with_oauth's User+
    OAuthAccount commit is atomic with itself, but membership
    provisioning is a separate step after it, not a new PR7 transaction
    boundary), the request must fail outright: no access_token is ever
    returned to the caller."""
    ctx = _org_with_saml_login(client, idp_keys)
    email = _new_email()

    from app.services import org_service

    def _boom(db, organization_id, user_id):
        raise RuntimeError("simulated membership provisioning failure")

    monkeypatch.setattr(org_service, "jit_provision_membership", _boom)

    with pytest.raises(RuntimeError):
        _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    # No token was ever issued for this identity -- confirmed by the
    # raised exception itself (no 200 response was ever produced).
    # The user row may exist (create_user_with_oauth already committed
    # it, same as OIDC's own architecture), but must have no membership.
    user = _user_by_email(email)
    if user is not None:
        assert _membership(ctx["org_id"], user.id) is None


# ── H. MFA ─────────────────────────────────────────────────────────────


@pytest.fixture
def configured_crypto(monkeypatch):
    from app.core import crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def test_jit_user_in_mfa_required_org_gets_enrollment_required_not_token(client, idp_keys, configured_crypto):
    """A brand-new SAML JIT user has never enrolled personal MFA -- if
    their (newly-granted) org membership belongs to an org with a
    required MFA policy, generate_tokens_or_mfa_challenge must still
    raise MFAEnrollmentRequiredError (403), exactly as it would for any
    other first-time login into that org. JIT provisioning must not be a
    way to bypass org-mandated MFA enrollment."""
    ctx = _org_with_saml_login(client, idp_keys)
    db = _DirectSession()
    try:
        db.add(OrganizationMFAPolicy(organization_id=ctx["org_id"], required=True))
        db.commit()
    finally:
        db.close()

    email = _new_email()
    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=email), ctx["relay_state"])

    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "mfa_enrollment_required"

    # Provisioning itself still happened (user+link+membership) -- only
    # token issuance was blocked, same as OIDC's own precedent.
    user = _user_by_email(email)
    assert user is not None
    assert _membership(ctx["org_id"], user.id) is not None


def test_mfa_enabled_linked_user_gets_challenge_not_token(client, idp_keys, configured_crypto):
    """Regression: an already-linked user (PR6 path) with personal MFA
    enabled must still get an MFA challenge on SAML login, unaffected by
    PR7's new third branch."""
    ctx = _org_with_saml_login(client, idp_keys)
    user = _register_and_login(client)
    headers = {"Authorization": f"Bearer {user['access_token']}"}

    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200

    db = _DirectSession()
    try:
        db.add(OAuthAccount(
            user_id=_user_id(client, user["access_token"]), provider="saml", provider_user_id=user["email"],
            email=user["email"], organization_saml_config_id=ctx["config_id"],
        ))
        db.commit()
    finally:
        db.close()

    resp = _post_acs(client, ctx["org_slug"], _build_response(ctx, idp_keys, name_id=user["email"]), ctx["relay_state"])

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "mfa_required"
    assert data["mfa_required"] is True
    assert "challenge_token" in data
    assert "access_token" not in data


# ── I. Existing OIDC/OAuth behavior unaffected ────────────────────────


def test_existing_oauth_login_unaffected_by_saml_jit_changes(client):
    user = _register_and_login(client)
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    assert "access_token" in resp.json()
