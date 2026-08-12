"""SAML SSO PR3+PR4: SP (Service Provider) metadata (PR3) and
SP-initiated login (PR4) -- no ACS/assertion-validation (PR5), identity
linking/JIT provisioning (PR6/PR7), CRUD API (PR8), or SLO (PR11) yet.

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
"""
from xml.sax.saxutils import escape as _xml_escape

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import OrganizationSAMLConfig

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
    """Not implemented yet (PR5) -- this is only the value the metadata
    document declares as where an IdP should POST its SAMLResponse,
    mirroring org_oidc_service.redirect_uri_for's identical role for the
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


def build_authn_request_url(org_slug: str, config: OrganizationSAMLConfig, relay_state: str) -> str:
    """Returns the redirect URL carrying this SP's SAMLRequest and the
    caller-provided (signed) RelayState, for `org_slug`'s registered IdP.
    Mirrors org_oidc_service.build_authorize_url's identical role for the
    existing OIDC login redirect -- a synchronous URL builder with no
    I/O: unlike OIDC's login step, SAML's SP-initiated AuthnRequest needs
    no token exchange to build; the redirect *is* the entire outbound
    half of this flow.

    OneLogin_Saml2_Auth.login()'s own docstring says it "returns
    Redirection URL" -- verified empirically (not assumed) against this
    exact installed version (1.16.0) that it never performs the HTTP
    redirect itself (no sys.exit/header emission anywhere in its call
    chain; OneLogin_Saml2_Utils.redirect just builds and returns the URL
    string), so routes_saml.py's caller wraps this in its own
    RedirectResponse, same as it already does for the metadata response.

    request_data is passed as {} -- verified empirically that
    OneLogin_Saml2_Auth.__init__ only stores it, unused on this call
    path: `config.sso_url` is always an absolute https:// URL, so the
    only code path that would need request_data
    (OneLogin_Saml2_Utils.get_self_url_host, for a relative redirect
    target) is never reached.

    No AuthnRequest signing (security.authnRequestsSigned stays at
    python3-saml's own default of False, same "no SP private key exists
    yet" reasoning _sp_settings_dict's own comment gives for metadata) --
    unsigned AuthnRequests are valid SAML, and this SP has no private key
    configured anywhere to sign with (PR2's own docstring already
    deferred that to "a later implementation step").
    """
    saml_settings = _authn_request_settings_dict(org_slug, config)
    auth = OneLogin_Saml2_Auth({}, old_settings=saml_settings)
    try:
        return auth.login(return_to=relay_state)
    except Exception as e:
        raise SAMLLoginError(f"could not construct SAML login request: {e}")
