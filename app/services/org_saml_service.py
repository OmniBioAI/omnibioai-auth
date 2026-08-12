"""SAML SSO PR3+PR4+PR5+PR6+PR7+PR8: SP metadata (PR3), SP-initiated
login (PR4), ACS/assertion validation (PR5), identity linking + JIT
provisioning (PR6/PR7), and organization-scoped CRUD (PR8) -- no SLO
(PR11) yet.

PR5's own hard boundary, load-bearing for the rest of this docstring:
validate_saml_response fully validates and extracts identity from an
IdP's SAMLResponse, but this module itself never calls find_linked_user/
create_user_with_oauth/issue_link_confirmation (app/services/
oauth_service.py) -- that decision tree lives in routes_saml.py's
_complete_saml_login (PR6+PR7), mirroring routes_sso.py's own
_complete_sso_flow, which similarly lives outside org_oidc_service.py.

PR6 added OAuthAccount.organization_saml_config_id (0022_oauth_saml_
config_id) precisely so those oauth_service.py functions CAN now be
called safely for provider="saml": that column is what scopes a NameID
lookup to one org's specific SAML IdP, the same role organization_sso_
config_id already plays for OIDC's `sub`. Passing an organization_saml_
configs.id into organization_sso_config_id instead would either violate
that column's own FK (if enforced) or, left NULL, collapse OAuthAccount's
uniqueness scoping back to a bare (provider, provider_user_id) pair --
reintroducing the exact cross-tenant NameID-collision bug organization_
sso_config_id was added to prevent for OIDC. Both scoping columns are
real, separate, mutually exclusive FKs (see oauth_service._assert_single_
idp_scope) -- not one column reused across two unrelated tables.

_complete_saml_login resolves an already-linked identity by logging in
directly, and an identity matching an existing account's email by
requiring the same explicit password confirmation (POST /auth/link/
confirm) OIDC/OAuth already use -- never a silent link. PR7 added the
third, remaining case: a never-seen-before identity (no link, no
matching email) is now JIT-provisioned -- a brand-new User + OAuthAccount
(provider="saml") + organization membership, through the exact same
create_user_with_oauth/jit_provision_membership/generate_tokens_or_mfa_
challenge choke points OIDC's own new-user branch already uses. See
_complete_saml_login's own docstring for the full decision tree, its
race handling, and why no attribute beyond the validated NameID is ever
trusted for provisioning.

build_sp_metadata (PR3) is deliberately independent of
`OrganizationSAMLConfig` (app/db/models.py) entirely -- it never queries
that table. SP metadata describes *this* SP's own identity (entity ID,
ACS URL, NameID format), not anything about a specific IdP; requiring an
OrganizationSAMLConfig row to already exist would be a chicken-and-egg
problem, since an org admin needs this document to hand to their IdP
administrator *before* they can fill in that IdP's own issued values
(entity_id/sso_url/x509_certificate) into a config row via the CRUD API
PR8 will add.

build_authn_request_url (PR4) is the first function in this module that
*does* need `OrganizationSAMLConfig` -- get_saml_config is the first
function here to take a `db: Session` at all, exactly what PR3's own
prior docstring anticipated ("no login path reads it yet"). The status
check itself (`config.status != "active"`) intentionally stays in
routes_saml.py, not here, mirroring org_sso_service.get_sso_config /
routes_sso.py's identical split for OIDC SSO.

Mirrors org_oidc_service.py's redirect_uri_for shape: pure, per-org URL
construction from settings.OAUTH_REDIRECT_BASE_URL -- the exact same base
URL already used for the existing OIDC SSO callback and the 3 global
OAuth providers' callback, not a new setting, since this is the same
"where this service is externally reachable" value either way.

PR8 (create_saml_config/update_saml_config/delete_saml_config) is
deliberately narrower than org_sso_service.py's OIDC equivalents: there
is no discovery/verification network call here at all (SAML has no
`.well-known` analogue, and PR8's own task spec explicitly forbids
introducing IdP metadata-URL fetching -- an SSRF surface OIDC's issuer
discovery already has to defend against via _assert_not_ssrf_target,
that this module has no reason to ever grow). An admin pastes their
IdP's already-issued entity_id/sso_url/x509_certificate directly; the
only validation performed is structural (URL shape, non-empty PEM
markers), not a live round-trip to the IdP. Because there is no
verification step to gate on, create_saml_config sets status="active"
immediately (the honest state: the trust material is captured and
ready), unlike configure_sso's status="active" being the *outcome of* a
successful discovery call.
"""
from datetime import datetime
from urllib.parse import urlparse
from xml.sax.saxutils import escape as _xml_escape

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from sqlalchemy.orm import Session

from app.core import token_revocation
from app.core.config import settings
from app.db.models import OrganizationSAMLConfig
from app.services import audit_service
from app.services.audit_service import AuditEventType

# SAML V2.0 Metadata Interoperability Profile (OASIS) specifies this as
# the correct media type for a metadata document -- not application/xml
# or text/xml, which some IdPs also accept but which isn't what the spec
# itself defines.
SP_METADATA_CONTENT_TYPE = "application/samlmetadata+xml"

_ACS_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

# The plan (see OrganizationSAMLConfig.attribute_mapping's own example
# shape, app/db/models.py: {"email": "NameID", ...}) is for NameID to
# carry the assertion's email address -- declaring that in metadata up
# front tells the IdP administrator what to configure, and any real
# assertion processing in a later PR (PR5) can rely on this service's
# own declared expectation instead of guessing.
_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


class SAMLMetadataError(Exception):
    """Raised if python3-saml itself reports the constructed metadata as
    invalid (schema/settings error) -- should never happen for the fixed,
    non-admin-controlled shape this module builds (org_slug is the only
    variable input, and it only ever changes URL path segments), but
    surfaced loudly rather than silently returning malformed metadata to
    an IdP administrator if it ever does."""


def entity_id_for(org_slug: str) -> str:
    """The SP's own metadata URL, used as its entityID -- a common, valid
    SAML convention (unique per org by construction, and self-describing/
    resolvable, unlike an arbitrary opaque string)."""
    return f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/saml/{org_slug}/metadata"


def acs_url_for(org_slug: str) -> str:
    """This SP's ACS endpoint for `org_slug` -- the value the metadata
    document declares as where an IdP should POST its SAMLResponse
    (PR3), the AuthnRequest's own AssertionConsumerServiceURL (PR4), and
    (PR5) the canonical URL _acs_request_data below constructs
    request_data from, so Destination/Recipient validation checks the
    SAMLResponse against this SP's own fixed, deterministic ACS URL --
    not whatever Host header a given live request happens to carry.
    Mirrors org_oidc_service.redirect_uri_for's identical role for the
    existing OIDC callback."""
    return f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/saml/{org_slug}/acs"


# python3-saml's OneLogin_Saml2_Settings.builder() (onelogin/saml2/
# metadata.py) inserts sp['entityId'] and the ACS Location directly into
# its XML template via raw Python %-string formatting -- verified
# empirically (not assumed) by reading that source: it applies no
# escaping of its own. org_slug -- the only variable input to
# entity_id_for/acs_url_for -- has no format restriction anywhere in the
# schema or DB layer (OrganizationCreate.slug is a bare `str`,
# organizations.slug is just VARCHAR(100) UNIQUE), so a slug containing
# XML metacharacters would otherwise reach that template unescaped,
# producing malformed metadata (observed: HTTP 500) or, for a slug that
# happens to form well-formed XML on its own, structurally altering the
# document served from this public endpoint. Escaping happens here, at
# the one place these values are embedded into XML -- entity_id_for/
# acs_url_for themselves stay pure, unescaped URL builders, since other
# callers (e.g. a future ACS route comparing against a request path)
# need the real URL, not an XML-escaped one.
_XML_ATTR_ESCAPES = {'"': "&quot;", "'": "&apos;"}


def _xml_escape_attr(value: str) -> str:
    """Escapes `value` for safe embedding as an XML attribute value.
    `xml.sax.saxutils.escape` covers &/</> by default; the extra map
    covers the two quote characters, since both entityID and the ACS
    Location are embedded in double-quoted XML attributes."""
    return _xml_escape(value, _XML_ATTR_ESCAPES)


def _sp_settings_dict(org_slug: str) -> dict:
    return {
        "sp": {
            "entityId": _xml_escape_attr(entity_id_for(org_slug)),
            "assertionConsumerService": {
                "url": _xml_escape_attr(acs_url_for(org_slug)),
                "binding": _ACS_BINDING,
            },
            "NameIDFormat": _NAME_ID_FORMAT,
            # No SP private key or certificate: PR2's own docstring
            # already deferred this ("environment/deployment
            # configuration, to be handled in a later implementation
            # step") -- unsigned metadata / unsigned AuthnRequests are
            # valid SAML, and every setting that would require a key to
            # back it (AuthnRequestsSigned, signMetadata,
            # wantAssertionsSigned as something *this* SP enforces)
            # stays at python3-saml's own default of False rather than
            # being turned on without a key to actually sign with.
            "x509cert": "",
            "privateKey": "",
        },
    }


def build_sp_metadata(org_slug: str) -> str:
    """Returns this SP's metadata XML for `org_slug`, independent of
    whether that org has an OrganizationSAMLConfig row yet (see module
    docstring). Raises SAMLMetadataError if python3-saml itself reports
    the constructed document as invalid -- verified empirically (not
    assumed) that sp_validation_only=True lets Settings construct with
    no `idp` block and an empty x509cert/privateKey, and that
    get_sp_metadata() + validate_metadata() together produce zero errors
    for exactly this shape.

    Returns `str`, not `bytes` -- python3-saml 1.16.0's own
    get_sp_metadata() returns str (confirmed empirically; earlier
    python3-saml releases historically returned bytes here, which is
    why this is called out explicitly rather than left to infer from a
    type hint alone). FastAPI's Response accepts either for `content=`,
    so routes_saml.py's caller is unaffected either way.
    """
    saml_settings = OneLogin_Saml2_Settings(_sp_settings_dict(org_slug), sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise SAMLMetadataError(f"invalid SP metadata generated: {errors}")
    return metadata


class SAMLLoginError(Exception):
    """Raised if python3-saml itself fails to construct the AuthnRequest
    redirect -- mirrors SAMLMetadataError's reasoning (surfaced loudly
    rather than silently producing a broken or malformed redirect)."""


def get_saml_config(db: Session, organization_id: int) -> OrganizationSAMLConfig | None:
    """The first function in this module to take a `db: Session` -- see
    module docstring. Mirrors org_sso_service.get_sso_config's identical
    shape; the active/inactive status check deliberately stays out of
    this query, same split routes_sso.py's sso_login uses for
    OrganizationSSOConfig."""
    return (
        db.query(OrganizationSAMLConfig)
        .filter(OrganizationSAMLConfig.organization_id == organization_id)
        .first()
    )


# ---------------------------------------------------------------------------
# PR8: organization-scoped CRUD. See module docstring for why this has no
# discovery/verification network call, unlike org_sso_service.py's OIDC
# equivalents.
# ---------------------------------------------------------------------------


class SAMLConfigValidationError(Exception):
    """Raised for any structural validation failure on admin-supplied
    entity_id/sso_url/x509_certificate -- the message is safe to return
    directly to the caller (an org admin), never internal detail."""


def _validate_sso_url(sso_url: str) -> None:
    """Structural-only: scheme + hostname shape, same as org_sso_
    service._validate_issuer_url's own first half. Deliberately does NOT
    reuse that function's second half (_assert_not_ssrf_target) -- this
    value is never fetched by this service (no discovery call exists for
    SAML), so there is no SSRF surface to defend here; a DNS-resolution
    check would be pure overhead with no security benefit. Reuses the
    same REQUIRE_HTTPS_FOR_SSO_ISSUER toggle OIDC's issuer validation
    already reads -- one "does this deployment require HTTPS for
    federation endpoints" knob, not a parallel SAML-only setting."""
    parsed = urlparse(sso_url)
    if parsed.scheme not in ("http", "https"):
        raise SAMLConfigValidationError("sso_url must be an http(s) URL")
    if settings.REQUIRE_HTTPS_FOR_SSO_ISSUER and parsed.scheme != "https":
        raise SAMLConfigValidationError("sso_url must use HTTPS")
    if not parsed.hostname:
        raise SAMLConfigValidationError("sso_url must include a hostname")


def _validate_x509_certificate(x509_certificate: str) -> None:
    """Basic PEM-shape validation only -- this codebase has no existing
    precedent anywhere in app/ (as opposed to tests, which build real
    certs for signing) for parsing X.509 with the `cryptography` library,
    and PR8's own task spec explicitly warns against over-engineering
    certificate parsing with no repository precedent. This catches the
    obvious case (empty, or not a PEM certificate block at all) without
    introducing ASN.1 parsing this module has never needed before real
    signature validation (PR5's OneLogin_Saml2_Auth, which does its own,
    separate, already-correct parsing) runs against it."""
    stripped = x509_certificate.strip()
    if "-----BEGIN CERTIFICATE-----" not in stripped or "-----END CERTIFICATE-----" not in stripped:
        raise SAMLConfigValidationError("x509_certificate must be a PEM-encoded certificate")


_VALID_STATUSES = ("pending_verification", "active", "disabled")


def _validate_status(status: str) -> None:
    if status not in _VALID_STATUSES:
        raise SAMLConfigValidationError(f"status must be one of: {', '.join(_VALID_STATUSES)}")


def create_saml_config(
    db: Session,
    organization_id: int,
    entity_id: str,
    sso_url: str,
    x509_certificate: str,
    attribute_mapping: dict | None,
    actor_user_id: int,
) -> OrganizationSAMLConfig:
    """Creates the org's SAML config. Raises ValueError if one already
    exists (one IdP per org -- organization_id is UNIQUE, same as
    org_sso_service.configure_sso's identical guard), or
    SAMLConfigValidationError if entity_id/sso_url/x509_certificate fail
    structural validation. Neither path writes a row.

    status="active" immediately -- see module docstring for why this
    differs from configure_sso's status="active"-as-discovery-outcome:
    there is nothing here to verify before persisting."""
    if get_saml_config(db, organization_id) is not None:
        raise ValueError("this organization already has a SAML configuration")

    if not entity_id.strip():
        raise SAMLConfigValidationError("entity_id must not be empty")
    _validate_sso_url(sso_url)
    _validate_x509_certificate(x509_certificate)

    now = datetime.utcnow()
    config = OrganizationSAMLConfig(
        organization_id=organization_id,
        entity_id=entity_id,
        sso_url=sso_url,
        x509_certificate=x509_certificate,
        attribute_mapping=attribute_mapping,
        status="active",
        created_at=now,
        updated_at=now,
        updated_by_user_id=actor_user_id,
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    # x509_certificate is a public certificate, not a secret -- safe in
    # audit metadata, unlike configure_sso's own deliberate omission of
    # client_secret/client_secret_encrypted.
    audit_service.log_event(
        db, AuditEventType.SAML_CONFIGURATION_CREATED, actor_user_id=actor_user_id,
        organization_id=organization_id, resource_type="organization_saml_config", resource_id=config.id,
        after_state={"entity_id": config.entity_id, "sso_url": config.sso_url, "status": config.status},
        metadata={"entity_id": config.entity_id},
    )
    return config


def update_saml_config(
    db: Session,
    config: OrganizationSAMLConfig,
    actor_user_id: int,
    entity_id: str | None = None,
    sso_url: str | None = None,
    x509_certificate: str | None = None,
    attribute_mapping: dict | None = None,
    enabled: bool | None = None,
    status: str | None = None,
) -> OrganizationSAMLConfig:
    """Only touches fields actually supplied (None = leave unchanged),
    same convention as org_sso_service.update_sso_config /
    config_service.update_config. Raises SAMLConfigValidationError before
    touching the row at all if a supplied field fails validation -- the
    existing config is left exactly as it was, not partially updated,
    same guarantee update_sso_config gives for a failed re-discovery."""
    if entity_id is not None and not entity_id.strip():
        raise SAMLConfigValidationError("entity_id must not be empty")
    if sso_url is not None:
        _validate_sso_url(sso_url)
    if x509_certificate is not None:
        _validate_x509_certificate(x509_certificate)
    if status is not None:
        _validate_status(status)

    before_entity_id, before_sso_url, before_status = config.entity_id, config.sso_url, config.status

    if entity_id is not None:
        config.entity_id = entity_id
    if sso_url is not None:
        config.sso_url = sso_url
    if x509_certificate is not None:
        config.x509_certificate = x509_certificate
    if attribute_mapping is not None:
        config.attribute_mapping = attribute_mapping
    if enabled is not None:
        config.enabled = enabled
    if status is not None:
        config.status = status

    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = actor_user_id
    db.commit()
    db.refresh(config)
    # Emitted unconditionally, same as update_sso_config's own reasoning
    # -- a no-op resupply is rare enough not to warrant tracking per-field
    # dirtiness just to suppress one audit row.
    audit_service.log_event(
        db, AuditEventType.SAML_CONFIGURATION_UPDATED, actor_user_id=actor_user_id,
        organization_id=config.organization_id, resource_type="organization_saml_config", resource_id=config.id,
        before_state={"entity_id": before_entity_id, "sso_url": before_sso_url, "status": before_status},
        after_state={"entity_id": config.entity_id, "sso_url": config.sso_url, "status": config.status},
        metadata={"entity_id": config.entity_id},
    )
    return config


def delete_saml_config(db: Session, config: OrganizationSAMLConfig) -> None:
    # No audit event -- mirrors org_sso_service.delete_sso_config's own,
    # identical lack of one exactly, a discovered pre-existing gap in the
    # OIDC precedent this PR follows rather than silently diverging from
    # in one direction only. See app/api/routes_org_saml.py's own PR8
    # report for this finding.
    db.delete(config)
    db.commit()


def _authn_request_settings_dict(org_slug: str, config: OrganizationSAMLConfig) -> dict:
    """Full SP+IdP settings for AuthnRequest generation. Reuses
    _sp_settings_dict's already-escaped `sp` block as-is -- PR3's XML-
    escaping boundary applies here too: OneLogin_Saml2_Auth.login()
    substitutes entityId/AssertionConsumerServiceURL into the AuthnRequest
    XML template the exact same unescaped-%-string-formatting way
    OneLogin_Saml2_Settings.builder() does for metadata (verified
    empirically by reading onelogin/saml2/xml_templates.py's
    AUTHN_REQUEST template -- not assumed), so this reuse is what keeps
    PR4 safe against the identical XML-injection-via-org_slug class of
    defect PR3's own fix addressed, without writing any new escaping
    logic here. `idp` comes entirely from `config` -- the org's own
    registered SAML identity provider, resolved server-side from the
    database by the caller, never client-supplied.
    """
    settings_dict = _sp_settings_dict(org_slug)
    settings_dict["idp"] = {
        "entityId": config.entity_id,
        "singleSignOnService": {"url": config.sso_url},
        "x509cert": config.x509_certificate,
    }
    return settings_dict


def build_authn_request_url(
    org_slug: str, config: OrganizationSAMLConfig, relay_state_for_request_id
) -> str:
    """Returns the redirect URL carrying this SP's SAMLRequest and a
    caller-provided (signed) RelayState, for `org_slug`'s registered IdP.
    Mirrors org_oidc_service.build_authorize_url's identical role for the
    existing OIDC login redirect -- a synchronous URL builder with no
    I/O: unlike OIDC's login step, SAML's SP-initiated AuthnRequest needs
    no token exchange to build; the redirect *is* the entire outbound
    half of this flow.

    relay_state_for_request_id: callable(request_id: str) -> str.
    PR5 addition, replacing this function's original PR4 signature
    (`relay_state: str`) -- create_saml_relay_state_token now embeds the
    AuthnRequest's own ID (so PR5's ACS handler can validate InResponseTo
    for real, instead of skipping that check), but that ID does not
    exist until the AuthnRequest itself has been constructed, and
    OneLogin_Saml2_Auth.login() generates the ID and builds+returns the
    final URL together, with no seam to inject an ID-dependent
    RelayState in between. This function therefore uses
    OneLogin_Saml2_Authn_Request directly (still python3-saml's own
    public, documented class -- not hand-rolled XML) so the ID is
    available before RelayState needs to be finalized: build the
    request, capture its ID, call the caller-supplied builder for the
    RelayState, then assemble the same redirect URL OneLogin_Saml2_Auth.
    login() itself would have produced (verified empirically that this
    reordering produces byte-identical AuthnRequest XML and URL
    structure to going through .login() directly, for the same settings
    and RelayState value).

    request_data passed to OneLogin_Saml2_Utils.redirect is {} --
    verified empirically that it's only consulted for a relative
    redirect target; `config.sso_url` is always an absolute https:// URL,
    so that path is never reached here.

    No AuthnRequest signing (security.authnRequestsSigned stays at
    python3-saml's own default of False, same "no SP private key exists
    yet" reasoning _sp_settings_dict's own comment gives for metadata) --
    unsigned AuthnRequests are valid SAML, and this SP has no private key
    configured anywhere to sign with (PR2's own docstring already
    deferred that to "a later implementation step").
    """
    saml_settings = OneLogin_Saml2_Settings(_authn_request_settings_dict(org_slug, config))
    try:
        authn_request = OneLogin_Saml2_Authn_Request(saml_settings)
        relay_state = relay_state_for_request_id(authn_request.get_id())
        return OneLogin_Saml2_Utils.redirect(
            saml_settings.get_idp_sso_url(),
            {"SAMLRequest": authn_request.get_request(), "RelayState": relay_state},
            request_data={},
        )
    except Exception as e:
        raise SAMLLoginError(f"could not construct SAML login request: {e}")


# ── PR5: ACS / assertion validation ─────────────────────────────────────


class SAMLAssertionError(Exception):
    """Raised for any failure validating an IdP's SAMLResponse -- signature,
    audience, destination, recipient, issuer, InResponseTo, time validity,
    or replay. Deliberately one exception type for all of these (mirrors
    org_oidc_service.SSOLoginError's identical "any failure exchanging or
    validating an enterprise IdP's response" role) -- routes_saml.py's ACS
    route catches this once and returns one generic 4xx, on purpose: which
    specific SAML validation rule failed is never returned to the caller
    (see routes_saml.py's own comment for why), so collapsing every
    failure mode into one exception type here costs nothing at the route
    layer and avoids the route needing to know python3-saml's internal
    error taxonomy at all.
    """


class SAMLIdentity:
    """The identity python3-saml actually extracted from a *successfully
    validated* SAMLResponse -- never constructed from anything that
    hasn't passed OneLogin_Saml2_Auth.is_authenticated() first (see
    validate_saml_response, the only place this is built). Deliberately
    a plain, small, immutable-by-convention holder, not a schema/ORM
    model -- this class itself never persists anything (see module
    docstring: persisting a SAML identity via OAuthAccount happens in
    routes_saml.py's _complete_saml_login, PR6+PR7).
    """

    __slots__ = ("assertion_id", "attributes", "name_id", "name_id_format", "session_index")

    def __init__(self, name_id, name_id_format, attributes, assertion_id, session_index):
        self.name_id = name_id
        self.name_id_format = name_id_format
        self.attributes = attributes
        self.assertion_id = assertion_id
        self.session_index = session_index


# Explicit, not left to python3-saml's own defaults (verified empirically
# via app/../onelogin/saml2/settings.py's _add_default_values --
# wantAssertionsSigned defaults to False there) -- see validate_saml_response's
# own docstring for why each of these is set the way it is.
_ACS_SECURITY_SETTINGS = {
    # The one setting that matters most: without this, is_valid()'s own
    # unconditional signature check ("No Signature found. SAML Response
    # rejected") is satisfied by a signed *Response* wrapping an
    # *unsigned* Assertion -- but this module reads identity out of the
    # Assertion specifically, so the Assertion itself, not just the
    # Response envelope, must be signed and verified against
    # OrganizationSAMLConfig.x509_certificate (the trust anchor).
    "wantAssertionsSigned": True,
    # Not required in addition to the above -- requiring both would
    # reject real IdPs (Okta, Entra ID, ADFS all commonly sign only the
    # Assertion, not the outer Response) for no security benefit once
    # the Assertion itself is verified.
    "wantMessagesSigned": False,
    "wantNameIdEncrypted": False,
    "wantAssertionsEncrypted": False,
    # This SP's identity model is NameID-based (PR3's own NameIDFormat
    # declaration, "email address"), not attribute-based -- attributes
    # are optional supplementary data here, not a requirement, so a
    # minimal IdP response carrying only a NameID must still validate.
    "wantAttributeStatement": False,
    # Same "never trust a weak/legacy algorithm" principle
    # org_oidc_service._ALLOWED_ID_TOKEN_ALGORITHMS already applies to
    # OIDC id_token signatures, applied here to SAML signature/digest
    # algorithms instead (rejects SHA1/DSA and other deprecated choices
    # python3-saml itself still permits by default).
    "rejectDeprecatedAlgorithm": True,
}


def _acs_settings_dict(org_slug: str, config: OrganizationSAMLConfig) -> dict:
    """Full SP+IdP+security settings for ACS validation. Reuses the same
    escaped `sp` block and `idp` block shape build_authn_request_url's
    own _authn_request_settings_dict already establishes -- entityId/ACS
    URL must match between the AuthnRequest this SP sent and the
    Response it's now validating, or a genuine (not attacker-crafted)
    audience/recipient mismatch would result.
    """
    settings_dict = _authn_request_settings_dict(org_slug, config)
    settings_dict["security"] = dict(_ACS_SECURITY_SETTINGS)
    return settings_dict


def _acs_request_data(org_slug: str, saml_response_b64: str, relay_state: str | None) -> dict:
    """Builds OneLogin_Saml2_Auth's request_data from this SP's own fixed,
    canonical acs_url_for(org_slug) -- deliberately NOT from the live
    HTTP request's own Host/scheme headers. Destination and Recipient
    validation (response.py's is_valid) both compare the SAMLResponse
    against whatever URL this dict implies is "the current endpoint" --
    building that from our own trusted, static OAUTH_REDIRECT_BASE_URL
    setting means those checks verify the assertion against this SP's
    real, deployed ACS URL, not against whatever a possibly-untrusted or
    misconfigured reverse-proxy Host header happened to report for a
    given request. Same "static base URL, not request introspection"
    convention entity_id_for/acs_url_for/build_authorize_url already use
    throughout this codebase.
    """
    acs_url = urlparse(acs_url_for(org_slug))
    return {
        "https": "on" if acs_url.scheme == "https" else "off",
        "http_host": acs_url.netloc,
        "script_name": acs_url.path,
        "post_data": {
            "SAMLResponse": saml_response_b64,
            **({"RelayState": relay_state} if relay_state else {}),
        },
    }


# TTL matches create_saml_relay_state_token's own 10-minute RelayState
# expiry for the same login transaction -- generous relative to any real
# IdP's NotOnOrAfter window (typically 2-5 minutes), so a key never
# needs to outlive the assertion it guards, and never accumulates
# unbounded (see _reject_if_replayed's own docstring for why Redis, not
# an in-memory structure or a new MySQL table, is the right store here).
_SAML_REPLAY_TTL_SECONDS = 600


def _reject_if_replayed(organization_id: int, organization_saml_config_id: int, assertion_id: str) -> None:
    """Atomic set-if-absent against the same Redis connection
    app.core.token_revocation already uses for the access-token
    blacklist -- reusing that established connection/keyspace (distinct
    key prefix below, zero collision risk with "blacklist:jti:...") is
    the smallest safe implementation available, rather than opening a
    second Redis client for what is architecturally the same kind of
    "has this identifier already been consumed" check. Searched first
    (not assumed): this repo has no generic one-time-token/nonce
    facility and no other durable replay-protection precedent anywhere
    -- token_revocation._blacklist is the closest and only fit, already
    exercised in tests via the exact same TestClient fixture (see
    tests/conftest.py) this function's tests reuse.

    Keyed by organization_id + organization_saml_config_id +
    assertion_id together, not assertion_id alone -- binds the replay
    check to the specific org/config a login transaction resolved to, so
    a (however astronomically unlikely) assertion-ID collision between
    two unrelated IdPs can never cross-reject or cross-accept between
    organizations.

    Deliberately fails CLOSED -- the opposite of token_revocation's own
    blacklist check, which fails open, and that asymmetry is
    intentional, not an inconsistency: see
    token_revocation.assert_token_usable's own docstring, which already
    draws exactly this line (Redis-only checks fail open; checks whose
    failure "would newly mask a real problem" do not). A Redis outage
    here failing open would mean a captured/replayed SAMLResponse could
    authenticate repeatedly for as long as Redis stays unreachable --
    silently defeating the one guarantee this function exists to
    provide -- so an unreachable store must reject the login attempt,
    not silently accept it.
    """
    key = f"saml_replay:{organization_id}:{organization_saml_config_id}:{assertion_id}"
    try:
        set_ok = token_revocation._blacklist.set(key, "1", nx=True, ex=_SAML_REPLAY_TTL_SECONDS)
    except Exception as e:
        raise SAMLAssertionError("could not verify this SAML assertion has not already been used") from e
    if not set_ok:
        raise SAMLAssertionError("this SAML assertion has already been used")


def validate_saml_response(
    org_slug: str,
    config: OrganizationSAMLConfig,
    saml_response_b64: str,
    relay_state: str | None,
    request_id: str,
) -> SAMLIdentity:
    """Fully validates an IdP's SAMLResponse and returns the identity it
    carries. Raises SAMLAssertionError -- and only SAMLAssertionError --
    for every failure mode: malformed/unparseable response, invalid or
    missing XML signature (validated against
    OrganizationSAMLConfig.x509_certificate, the trust anchor -- this
    function never trusts a certificate embedded in the response itself,
    since python3-saml's own signature validation is keyed off
    idp['x509cert'] from settings, not from anything inside the document
    being validated), wrong audience, wrong destination/recipient, wrong
    issuer, wrong or missing InResponseTo, expired or not-yet-valid
    assertion, and replayed assertion -- in that order, since replay
    protection only runs once every other check above has already
    proven the assertion authentic (checking replay first would let an
    attacker pollute or probe the replay store with unvalidated,
    unsigned garbage).

    All of the above (except replay, PR5's own addition) come from
    OneLogin_Saml2_Auth.process_response()/response.is_valid() with
    strict=True (this module's default -- never relaxed) -- verified by
    reading response.py directly, not assumed: is_valid() itself checks
    SAML version, response ID, status, assertion count, XSD schema
    (strict mode), InResponseTo, Conditions presence, timestamps,
    AuthnStatement presence, SubjectConfirmation (Recipient + InResponseTo
    + NotBefore/NotOnOrAfter), signature requirements (per
    _ACS_SECURITY_SETTINGS), Destination, audience, and issuer -- this
    function does not reimplement or duplicate any of that logic by hand.

    Clock skew: python3-saml 1.16.0 has exactly one clock-skew tolerance,
    OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT = 300 (seconds) --
    verified empirically (an initial "no tolerance anywhere" read of this
    library was wrong; a targeted grep for "clock"/"skew" misses this
    constant's actual name) by both reading response.py's
    validate_timestamps() and, more importantly, proving the exact
    boundary against a real signed assertion: a Conditions NotBefore 120s
    in the future is accepted (within the 300s drift allowance), one 600s
    in the future is rejected. This tolerance applies ONLY to the
    Assertion's own <Conditions> NotBefore/NotOnOrAfter -- it is a fixed
    library constant, not something this module's settings dict can
    configure away or widen. SubjectConfirmationData's NotBefore/
    NotOnOrAfter (the bearer-confirmation window, arguably the more
    security-load-bearing of the two) gets NO drift allowance at all --
    exact real-time comparison, also verified empirically. No attempt is
    made to hand-roll a different tolerance around either check: doing so
    would mean re-validating (and potentially weakening) exactly the
    timestamp logic this function relies on the library to get right.
    """
    saml_settings = _acs_settings_dict(org_slug, config)
    request_data = _acs_request_data(org_slug, saml_response_b64, relay_state)
    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)

    try:
        auth.process_response(request_id=request_id)
    except Exception as e:
        raise SAMLAssertionError("could not process SAML response") from e

    if auth.get_errors() or not auth.is_authenticated():
        raise SAMLAssertionError("SAML assertion failed validation")

    name_id = auth.get_nameid()
    if not name_id:
        raise SAMLAssertionError("SAML assertion did not include a NameID")

    assertion_id = auth.get_last_assertion_id()
    if not assertion_id:
        raise SAMLAssertionError("SAML assertion is missing an ID")

    _reject_if_replayed(config.organization_id, config.id, assertion_id)

    return SAMLIdentity(
        name_id=name_id,
        name_id_format=auth.get_nameid_format(),
        attributes=auth.get_attributes(),
        assertion_id=assertion_id,
        session_index=auth.get_session_index(),
    )
