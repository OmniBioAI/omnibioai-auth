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
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
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
# PR11 (SLO): HTTP-Redirect, not HTTP-POST -- verified by reading
# OneLogin_Saml2_Auth.process_slo directly, which only reads SAMLRequest/
# SAMLResponse from `get_data` (query-string parameters) and explicitly
# raises "Only supported HTTP_REDIRECT Binding" for anything else. This
# is also the binding real IdPs (Okta, Entra ID, ADFS) commonly expect
# for SLO regardless of what they used for login.
_SLO_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

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


def slo_url_for(org_slug: str) -> str:
    """This SP's own Single Logout Service endpoint for `org_slug` (PR11)
    -- declared in SP metadata so an IdP administrator can configure
    where to send both directions of SLO (an unsolicited LogoutRequest,
    or this SP's own LogoutResponse reply to one), and the canonical URL
    the Destination check on an incoming LogoutRequest is validated
    against. Same "static base URL, not request introspection"
    convention as acs_url_for."""
    return f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/saml/{org_slug}/slo"


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
            # PR11 (SLO): declared unconditionally, same as
            # assertionConsumerService above -- this SP's own SLO
            # endpoint always exists at this fixed URL regardless of
            # whether any org's IdP is configured to use it yet (an IdP
            # administrator reading this SP's metadata is exactly how
            # they'd learn to configure it in the first place).
            "singleLogoutService": {
                "url": _xml_escape_attr(slo_url_for(org_slug)),
                "binding": _SLO_BINDING,
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
    slo_url: str | None = None,
) -> OrganizationSAMLConfig:
    """Creates the org's SAML config. Raises ValueError if one already
    exists (one IdP per org -- organization_id is UNIQUE, same as
    org_sso_service.configure_sso's identical guard), or
    SAMLConfigValidationError if entity_id/sso_url/x509_certificate (or,
    PR11, slo_url) fail structural validation. Neither path writes a
    row.

    status="active" immediately -- see module docstring for why this
    differs from configure_sso's status="active"-as-discovery-outcome:
    there is nothing here to verify before persisting.

    slo_url (PR11): optional, default None -- not every IdP supports or
    is configured for SLO. Validated with the identical _validate_sso_
    url structural check sso_url itself gets, same reasoning: both are
    admin-supplied IdP endpoint URLs, and this is the one validation
    boundary either needs.
    """
    if get_saml_config(db, organization_id) is not None:
        raise ValueError("this organization already has a SAML configuration")

    if not entity_id.strip():
        raise SAMLConfigValidationError("entity_id must not be empty")
    _validate_sso_url(sso_url)
    _validate_x509_certificate(x509_certificate)
    if slo_url is not None:
        _validate_sso_url(slo_url)

    now = datetime.utcnow()
    config = OrganizationSAMLConfig(
        organization_id=organization_id,
        entity_id=entity_id,
        sso_url=sso_url,
        x509_certificate=x509_certificate,
        attribute_mapping=attribute_mapping,
        status="active",
        slo_url=slo_url,
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
    slo_url: str | None = None,
) -> OrganizationSAMLConfig:
    """Only touches fields actually supplied (None = leave unchanged),
    same convention as org_sso_service.update_sso_config /
    config_service.update_config. Raises SAMLConfigValidationError before
    touching the row at all if a supplied field fails validation -- the
    existing config is left exactly as it was, not partially updated,
    same guarantee update_sso_config gives for a failed re-discovery.

    slo_url (PR11): same None-means-leave-unchanged convention as every
    other field here -- including the pre-existing limitation that
    follows from it: there is no way to explicitly clear slo_url back to
    NULL once set, the same limitation attribute_mapping already has.
    Not a new gap introduced by PR11, the established convention.
    """
    if entity_id is not None and not entity_id.strip():
        raise SAMLConfigValidationError("entity_id must not be empty")
    if sso_url is not None:
        _validate_sso_url(sso_url)
    if x509_certificate is not None:
        _validate_x509_certificate(x509_certificate)
    if status is not None:
        _validate_status(status)
    if slo_url is not None:
        _validate_sso_url(slo_url)

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
    if slo_url is not None:
        config.slo_url = slo_url
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


def _reject_if_replayed(
    organization_id: int,
    organization_saml_config_id: int,
    message_id: str,
    key_prefix: str = "saml_replay",
    error_cls: type = SAMLAssertionError,
) -> None:
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

    Keyed by organization_id + organization_saml_config_id + message_id
    together, not message_id alone -- binds the replay check to the
    specific org/config a login (or, PR11, logout) transaction resolved
    to, so a (however astronomically unlikely) ID collision between two
    unrelated IdPs can never cross-reject or cross-accept between
    organizations.

    Deliberately fails CLOSED -- the opposite of token_revocation's own
    blacklist check, which fails open, and that asymmetry is
    intentional, not an inconsistency: see
    token_revocation.assert_token_usable's own docstring, which already
    draws exactly this line (Redis-only checks fail open; checks whose
    failure "would newly mask a real problem" do not). A Redis outage
    here failing open would mean a captured/replayed SAML message could
    be consumed repeatedly for as long as Redis stays unreachable --
    silently defeating the one guarantee this function exists to
    provide -- so an unreachable store must reject the attempt, not
    silently accept it.

    key_prefix/error_cls (PR11): this same function, generalized rather
    than copy-pasted, also backs SLO's LogoutRequest replay protection
    (validate_slo_logout_request below) -- a LogoutRequest has no
    InResponseTo of its own to check (it's unsolicited by definition),
    so message-ID replay protection is the only defense against the
    same signed, valid LogoutRequest being resubmitted. Both defaults
    preserve this function's exact pre-PR11 behavior/key format for
    every existing ACS caller.
    """
    key = f"{key_prefix}:{organization_id}:{organization_saml_config_id}:{message_id}"
    try:
        set_ok = token_revocation._blacklist.set(key, "1", nx=True, ex=_SAML_REPLAY_TTL_SECONDS)
    except Exception as e:
        raise error_cls("could not verify this SAML message has not already been used") from e
    if not set_ok:
        raise error_cls("this SAML message has already been used")


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


# ── PR11: Single Logout (SLO) ────────────────────────────────────────────
#
# Verified directly against the installed python3-saml 1.16.0 source
# (onelogin/saml2/auth.py, logout_request.py, logout_response.py,
# settings.py) rather than assumed, the same discipline PR4/PR5 already
# applied to AuthnRequest/ACS:
#
#   - OneLogin_Saml2_Auth.process_slo only reads SAMLRequest/SAMLResponse
#     from `get_data` (query-string parameters) and explicitly raises
#     "Only supported HTTP_REDIRECT Binding" for anything else -- SLO in
#     this library is GET/query-string, never POST/form, unlike ACS.
#   - idp['singleLogoutService']['url'] is a genuinely separate settings
#     key from idp['singleSignOnService']['url'] (settings.py's own
#     get_idp_slo_url() returns None, not sso_url, when unset) -- the
#     existing OrganizationSAMLConfig.sso_url column cannot be reused for
#     this, hence the new slo_url column (0023_saml_slo).
#   - Validating an INCOMING IdP-signed LogoutRequest/LogoutResponse
#     needs only the IdP's x509cert (already have it, config.
#     x509_certificate) -- exactly the same trust anchor ACS already
#     uses for the assertion signature. No SP private key is required to
#     validate what we receive.
#   - Building an OUTGOING SP LogoutRequest/LogoutResponse only signs it
#     if security['logoutRequestSigned']/['logoutResponseSigned'] is
#     True; both stay at the library's own False default here, the
#     identical "no SP private key exists yet" position
#     build_authn_request_url's own docstring already documents for
#     AuthnRequest. See this PR's own report for why this is a
#     deliberate, disclosed scope boundary, not an oversight: some
#     strict IdPs may reject an unsigned SP LogoutRequest.
#   - Auth._validate_signature (used by both validate_request_signature/
#     validate_response_signature) silently returns True -- treats the
#     message as validly "signed" -- when NO Signature parameter is
#     present at all, UNLESS security['wantMessagesSigned'] is True.
#     This is the single most important setting in this section:
#     leaving it at the library's own False default would let anyone
#     submit a completely unsigned, forged LogoutRequest for an
#     arbitrary NameID and have it silently accepted -- a real,
#     unauthenticated session-termination attack against any user whose
#     NameID an attacker can guess (their own email address, in this
#     SP's NameID-is-email model). _SLO_SECURITY_SETTINGS below sets it
#     True unconditionally; there is no configuration path in this
#     module that leaves it False.

_SLO_SECURITY_SETTINGS = {
    # See this section's own module comment above for why this one
    # setting is load-bearing for the entire security model of
    # IdP-initiated SLO -- not merely "not left to the library default"
    # the way the rest of this dict is, but the one setting that
    # prevents an unsigned, forged LogoutRequest from being silently
    # accepted as valid.
    "wantMessagesSigned": True,
    # Outgoing only -- no SP private key exists (see module docstring's
    # own "later implementation step" deferral, unchanged since PR2).
    # Both explicit False, matching AuthnRequestsSigned's own precedent,
    # rather than left to infer from the library default.
    "logoutRequestSigned": False,
    "logoutResponseSigned": False,
    "rejectDeprecatedAlgorithm": True,
}


def _slo_settings_dict(org_slug: str, config: OrganizationSAMLConfig) -> dict:
    """Full SP+IdP+security settings for SLO. Reuses
    _authn_request_settings_dict's already-escaped `sp` block and `idp`
    entityId/x509cert -- the same trust anchor ACS already validates
    assertion signatures against now also validates LogoutRequest/
    LogoutResponse signatures.

    idp.singleLogoutService is added only when config.slo_url is set --
    deliberately NOT set to a None url when it isn't: validating an
    INCOMING LogoutRequest needs only entityId/x509cert (never the IdP's
    own SLO url), so a config with no configured slo_url can still
    correctly validate and process an IdP-initiated LogoutRequest, it
    just cannot be used to build an OUTGOING SP-initiated one (see
    build_logout_request_url's own explicit check for that).
    """
    settings_dict = _authn_request_settings_dict(org_slug, config)
    if config.slo_url:
        settings_dict["idp"]["singleLogoutService"] = {"url": config.slo_url, "binding": _SLO_BINDING}
    settings_dict["security"] = dict(_SLO_SECURITY_SETTINGS)
    return settings_dict


def _slo_request_data(org_slug: str, get_data: dict, query_string: str) -> dict:
    """Builds OneLogin_Saml2_Auth's request_data for SLO's GET/query-
    string binding -- the `get_data` analogue of _acs_request_data's
    `post_data`. https/http_host/script_name come from this SP's own
    fixed, canonical slo_url_for(org_slug) -- deliberately NOT from the
    live request's own Host/scheme headers, same "static base URL, not
    request introspection" convention _acs_request_data already follows,
    so Destination validation checks the incoming message against this
    SP's real, deployed SLO URL.

    validate_signature_from_qs=True: makes signature validation hash the
    RAW, byte-exact query string this request actually arrived with
    (query_string) rather than reconstructing one from the individual
    SAMLRequest/RelayState/SigAlg values -- avoids any re-encoding
    mismatch (whitespace, percent-encoding case, parameter order) that
    could cause a genuinely valid signature to fail re-validation, or
    (in the wrong direction) let a subtly-modified reconstruction
    validate when the original wouldn't have.
    """
    slo_url = urlparse(slo_url_for(org_slug))
    return {
        "https": "on" if slo_url.scheme == "https" else "off",
        "http_host": slo_url.netloc,
        "script_name": slo_url.path,
        "get_data": get_data,
        "query_string": query_string,
        "validate_signature_from_qs": True,
    }


class SAMLLogoutError(Exception):
    """Raised for any failure validating or constructing an SLO message
    (LogoutRequest or LogoutResponse, incoming or outgoing) -- mirrors
    SAMLAssertionError's identical "one exception type, no internal
    detail leaked" role for the login/ACS side. routes_saml.py's SLO
    endpoint catches this once and returns one generic 4xx, same
    reasoning SAMLAssertionError's own docstring gives.
    """


class SAMLLogoutRequestIdentity:
    """The identity + message ID extracted from a *successfully
    validated* incoming LogoutRequest -- never constructed from anything
    that hasn't passed validate_slo_logout_request's own signature/
    structural checks first. Same "plain, small, immutable-by-
    convention holder" shape as SAMLIdentity above."""

    __slots__ = ("name_id", "request_id", "session_index")

    def __init__(self, name_id, session_index, request_id):
        self.name_id = name_id
        self.session_index = session_index
        self.request_id = request_id


def build_logout_request_url(
    org_slug: str,
    config: OrganizationSAMLConfig,
    name_id: str,
    session_index: str | None,
    relay_state_for_request_id,
) -> str | None:
    """SP-initiated logout (PR11): returns the redirect URL carrying this
    SP's LogoutRequest and a caller-provided (signed) RelayState, for
    `org_slug`'s registered IdP. Mirrors build_authn_request_url's
    identical role/shape for AuthnRequest -- same "build the request,
    capture its ID, call the caller-supplied RelayState builder, then
    assemble the redirect" ordering, for the identical reason: the
    RelayState needs the LogoutRequest's own ID embedded (so the
    eventual LogoutResponse's InResponseTo can be validated for real),
    but that ID doesn't exist until the request itself has been built.

    Returns None -- not an error -- if this org's IdP has no configured
    SLO endpoint (config.slo_url). Not every real-world IdP supports or
    is configured for SLO; the caller (routes_saml.py's /logout) treats
    this as "no IdP-side logout available for this session," completing
    only the local logout it already performs regardless.

    No LogoutRequest signing (security.logoutRequestSigned stays False,
    _SLO_SECURITY_SETTINGS) -- see this section's own module comment for
    why: no SP private key exists anywhere in this deployment.
    """
    if not config.slo_url:
        return None

    saml_settings = OneLogin_Saml2_Settings(_slo_settings_dict(org_slug, config))
    try:
        logout_request = OneLogin_Saml2_Logout_Request(saml_settings, name_id=name_id, session_index=session_index)
        relay_state = relay_state_for_request_id(logout_request.id)
        return OneLogin_Saml2_Utils.redirect(
            saml_settings.get_idp_slo_url(),
            {"SAMLRequest": logout_request.get_request(), "RelayState": relay_state},
            request_data={},
        )
    except Exception as e:
        raise SAMLLogoutError(f"could not construct SAML logout request: {e}") from e


def validate_slo_logout_request(
    org_slug: str,
    config: OrganizationSAMLConfig,
    saml_request_b64: str,
    relay_state: str | None,
    sig_alg: str | None,
    signature: str | None,
    query_string: str,
) -> SAMLLogoutRequestIdentity:
    """IdP-initiated SLO (PR11): fully validates an unsolicited
    LogoutRequest from `org_slug`'s registered IdP and returns the
    identity + message ID it carries. Raises SAMLLogoutError -- and only
    SAMLLogoutError -- for every failure mode: invalid or missing
    signature (validated against config.x509_certificate, never a
    certificate embedded in the message itself, same trust-anchor
    discipline validate_saml_response's own docstring establishes for
    ACS), wrong destination, wrong issuer, expired, missing NameID,
    missing message ID, and replayed message -- checked in that order
    (replay last, only once the message is otherwise proven authentic --
    same ordering validate_saml_response already uses and the same
    reasoning: checking replay first would let an attacker pollute or
    probe the replay store with unvalidated, unsigned garbage).

    Two-step validation, decomposed from what OneLogin_Saml2_Auth.
    process_slo does as one monolithic call (verified by reading it
    directly) -- the same "use the library's lower-level classes
    directly for a needed seam" pattern build_authn_request_url already
    established relative to .login(): this function needs to insert its
    own session-lookup/revocation logic between "the LogoutRequest is
    valid" and "reply to the IdP," which process_slo's own all-in-one
    shape doesn't leave room for.

      1. auth.validate_request_signature -- the actual cryptographic
         check (Auth._validate_signature), keyed off idp['x509cert']
         from settings, exactly as ACS's signature validation is.
      2. logout_request.is_valid -- the structural checks (Destination,
         Issuer, NotOnOrAfter, and -- defense in depth alongside step 1
         -- the wantMessagesSigned-requires-a-Signature-parameter-at-all
         check).

    Never trusts a NameID/SessionIndex from anything that hasn't passed
    both checks above.
    """
    saml_settings = OneLogin_Saml2_Settings(_slo_settings_dict(org_slug, config))
    get_data = {"SAMLRequest": saml_request_b64}
    if relay_state:
        get_data["RelayState"] = relay_state
    if sig_alg:
        get_data["SigAlg"] = sig_alg
    if signature:
        get_data["Signature"] = signature
    request_data = _slo_request_data(org_slug, get_data, query_string)

    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    try:
        signature_ok = auth.validate_request_signature(get_data)
    except Exception as e:
        raise SAMLLogoutError("could not validate SAML LogoutRequest signature") from e
    if not signature_ok:
        raise SAMLLogoutError("SAML LogoutRequest signature validation failed")

    logout_request = OneLogin_Saml2_Logout_Request(saml_settings, request=saml_request_b64)
    try:
        structurally_valid = logout_request.is_valid(request_data)
    except Exception as e:
        raise SAMLLogoutError("SAML LogoutRequest failed validation") from e
    if not structurally_valid:
        raise SAMLLogoutError("SAML LogoutRequest failed validation")

    request_xml = logout_request.get_xml()
    name_id = OneLogin_Saml2_Logout_Request.get_nameid(request_xml)
    if not name_id:
        raise SAMLLogoutError("SAML LogoutRequest did not include a NameID")

    request_id = logout_request.id
    if not request_id:
        raise SAMLLogoutError("SAML LogoutRequest is missing an ID")

    _reject_if_replayed(
        config.organization_id, config.id, request_id,
        key_prefix="saml_slo_replay", error_cls=SAMLLogoutError,
    )

    session_indexes = OneLogin_Saml2_Logout_Request.get_session_indexes(request_xml)
    session_index = session_indexes[0] if session_indexes else None

    return SAMLLogoutRequestIdentity(name_id=name_id, session_index=session_index, request_id=request_id)


def build_slo_logout_response_redirect(org_slug: str, config: OrganizationSAMLConfig, in_response_to: str) -> str:
    """IdP-initiated SLO (PR11): builds this SP's reply to an already-
    validated LogoutRequest (validate_slo_logout_request must have
    already succeeded -- this function performs no validation of its
    own). Redirects to config.slo_url directly -- deliberately NOT to
    whatever RelayState the incoming LogoutRequest happened to carry
    (OneLogin_Saml2_Auth.process_slo's own convenience wrapper falls
    back to the request's RelayState when no explicit URL is available,
    which this module avoids by construction: an IdP-supplied value is
    a weaker, less deliberate redirect target than this SP's own
    server-resolved, admin-configured slo_url).

    Raises SAMLLogoutError if this org's IdP has no configured SLO
    endpoint -- there is nowhere to send the reply. In practice this
    should be unreachable in normal operation (an IdP without a
    configured slo_url has no URL of its own to have sent the
    LogoutRequest we're replying to from either), but fails closed
    rather than assuming that can never happen.

    No LogoutResponse signing (security.logoutResponseSigned stays
    False) -- same "no SP private key exists" reasoning as
    build_logout_request_url.
    """
    if not config.slo_url:
        raise SAMLLogoutError("this organization's SAML configuration does not support Single Logout")

    saml_settings = OneLogin_Saml2_Settings(_slo_settings_dict(org_slug, config))
    try:
        response_builder = OneLogin_Saml2_Logout_Response(saml_settings)
        response_builder.build(in_response_to)
        return OneLogin_Saml2_Utils.redirect(
            config.slo_url,
            {"SAMLResponse": response_builder.get_response()},
            request_data={},
        )
    except Exception as e:
        raise SAMLLogoutError(f"could not construct SAML logout response: {e}") from e


def validate_slo_logout_response(
    org_slug: str,
    config: OrganizationSAMLConfig,
    saml_response_b64: str,
    relay_state: str | None,
    request_id: str,
    sig_alg: str | None,
    signature: str | None,
    query_string: str,
) -> None:
    """SP-initiated SLO (PR11): validates the IdP's LogoutResponse
    completing a round trip this SP itself started
    (build_logout_request_url). Raises SAMLLogoutError -- and only
    SAMLLogoutError -- for an invalid/missing signature, a
    structurally-invalid response (Destination/Issuer/InResponseTo, the
    last checked against `request_id` -- the SP-generated LogoutRequest
    ID carried in the SLO RelayState token, the exact InResponseTo role
    request_id already plays for ACS), or a non-Success status.

    No replay protection here -- unlike validate_slo_logout_request
    (which protects an unsolicited LogoutRequest with no InResponseTo
    of its own), this response is already bound to a specific,
    single-use RelayState token (create_saml_slo_relay_state_token,
    10-minute expiry, decoded by the caller before this function ever
    runs) -- the same reasoning validate_saml_response's own
    InResponseTo check (via python3-saml's own replay-resistant
    request-ID matching) already relies on for ACS's SP-initiated login
    round trip, rather than needing a second, independent replay guard.

    Local session invalidation for the SP-initiated flow already
    happened in routes_saml.py's /logout, before this SP ever redirected
    the browser to the IdP -- this function's only job is confirming the
    IdP's own reply is genuine, not repeating that revocation.
    """
    saml_settings = OneLogin_Saml2_Settings(_slo_settings_dict(org_slug, config))
    get_data = {"SAMLResponse": saml_response_b64}
    if relay_state:
        get_data["RelayState"] = relay_state
    if sig_alg:
        get_data["SigAlg"] = sig_alg
    if signature:
        get_data["Signature"] = signature
    request_data = _slo_request_data(org_slug, get_data, query_string)

    auth = OneLogin_Saml2_Auth(request_data, old_settings=saml_settings)
    try:
        signature_ok = auth.validate_response_signature(get_data)
    except Exception as e:
        raise SAMLLogoutError("could not validate SAML LogoutResponse signature") from e
    if not signature_ok:
        raise SAMLLogoutError("SAML LogoutResponse signature validation failed")

    logout_response = OneLogin_Saml2_Logout_Response(saml_settings, response=saml_response_b64)
    try:
        structurally_valid = logout_response.is_valid(request_data, request_id=request_id)
    except Exception as e:
        raise SAMLLogoutError("SAML LogoutResponse failed validation") from e
    if not structurally_valid:
        raise SAMLLogoutError("SAML LogoutResponse failed validation")

    if logout_response.get_status() != OneLogin_Saml2_Constants.STATUS_SUCCESS:
        raise SAMLLogoutError("SAML LogoutResponse did not report success")
