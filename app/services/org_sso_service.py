import ipaddress
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import settings
from app.db.models import OAuthAccount, OrganizationSSOConfig
from app.services import audit_service
from app.services.audit_service import AuditEventType

_DISCOVERY_TIMEOUT_SECONDS = 5.0
_REQUIRED_DISCOVERY_FIELDS = ("authorization_endpoint", "token_endpoint", "jwks_uri")


class SSODiscoveryError(Exception):
    """Raised for any issuer-validation or OIDC-discovery failure. The
    message is safe to return directly to the caller (an org admin) --
    never internal detail like a raw exception repr or stack trace."""


def _validate_issuer_url(issuer: str) -> str:
    parsed = urlparse(issuer)
    if parsed.scheme not in ("http", "https"):
        raise SSODiscoveryError("issuer must be an http(s) URL")
    if settings.REQUIRE_HTTPS_FOR_SSO_ISSUER and parsed.scheme != "https":
        raise SSODiscoveryError("issuer must use HTTPS")
    if not parsed.hostname:
        raise SSODiscoveryError("issuer must include a hostname")
    return parsed.hostname


def _assert_not_ssrf_target(hostname: str) -> None:
    """Resolves hostname and rejects any target whose IP isn't globally
    routable -- issuer URL is admin-supplied, untrusted input (an org
    admin, not a superadmin), and this is the only network call in this
    service made to an address that kind of caller controls. `is_global`
    covers loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 --
    including the 169.254.169.254 cloud metadata endpoint -- and
    fe80::/10), private ranges (10/8, 172.16/12, 192.168/16, fc00::/7),
    and other non-routable/reserved space in one check, rather than
    maintaining a hand-rolled list that's one missed range away from a
    gap.

    Known residual gap: this validates the hostname's resolved IP at
    check time, then httpx resolves and connects to it independently a
    moment later -- a DNS-rebinding attacker (answer a public IP on the
    first lookup, a private one on the second) could still slip through.
    Fully closing that requires pinning the connection to the IP checked
    here (a custom httpx transport), which is out of scope for this PR;
    flagged explicitly rather than silently claimed as solved.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSODiscoveryError(f"could not resolve issuer host: {e}")

    for family, _, _, _, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise SSODiscoveryError("issuer host resolves to a non-public address, which is not allowed")


async def verify_oidc_discovery(issuer: str) -> dict:
    """Fetches and validates {issuer}/.well-known/openid-configuration.
    Raises SSODiscoveryError on any failure -- callers must not persist
    anything when this raises."""
    hostname = _validate_issuer_url(issuer)
    _assert_not_ssrf_target(hostname)

    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=_DISCOVERY_TIMEOUT_SECONDS) as client:
            # follow_redirects left at its default (False) deliberately --
            # an issuer that redirects elsewhere could otherwise be used
            # to reach a target this function never got to validate.
            resp = await client.get(discovery_url, follow_redirects=False)
    except httpx.HTTPError as e:
        raise SSODiscoveryError(f"could not reach discovery endpoint: {e}")

    if resp.status_code != 200:
        raise SSODiscoveryError(f"discovery endpoint returned HTTP {resp.status_code}")

    try:
        doc = resp.json()
    except ValueError:
        raise SSODiscoveryError("discovery endpoint did not return valid JSON")

    if doc.get("issuer") != issuer:
        raise SSODiscoveryError(
            f"discovery document's issuer ({doc.get('issuer')!r}) does not match the requested issuer ({issuer!r})"
        )

    missing = [f for f in _REQUIRED_DISCOVERY_FIELDS if not doc.get(f)]
    if missing:
        raise SSODiscoveryError(f"discovery document missing required field(s): {', '.join(missing)}")

    return doc


def get_sso_config(db: Session, organization_id: int) -> OrganizationSSOConfig | None:
    return (
        db.query(OrganizationSSOConfig)
        .filter(OrganizationSSOConfig.organization_id == organization_id)
        .first()
    )


async def configure_sso(
    db: Session,
    organization_id: int,
    issuer: str,
    client_id: str,
    client_secret: str,
    allowed_domains: list[str],
    actor_user_id: int,
) -> OrganizationSSOConfig:
    """Creates the org's SSO config. Raises ValueError if one already
    exists (one IdP per org -- organization_id is UNIQUE), or
    SSODiscoveryError if discovery fails. Neither path writes a row --
    a failed discovery attempt is never persisted.
    """
    if get_sso_config(db, organization_id) is not None:
        raise ValueError("this organization already has an SSO configuration")

    doc = await verify_oidc_discovery(issuer)
    now = datetime.utcnow()

    config = OrganizationSSOConfig(
        organization_id=organization_id,
        provider_type="oidc",
        issuer=issuer,
        client_id=client_id,
        client_secret_encrypted=crypto.encrypt(client_secret),
        authorization_endpoint=doc["authorization_endpoint"],
        token_endpoint=doc["token_endpoint"],
        userinfo_endpoint=doc.get("userinfo_endpoint"),
        jwks_uri=doc["jwks_uri"],
        allowed_domains=allowed_domains,
        status="active",
        created_at=now,
        updated_at=now,
        updated_by_user_id=actor_user_id,
        last_verified_at=now,
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    # PR11.4b: never client_secret/client_secret_encrypted or any token
    # in audit metadata -- provider_type and issuer are not secrets.
    audit_service.log_event(
        db, AuditEventType.SSO_CONFIGURATION_CREATED, actor_user_id=actor_user_id,
        organization_id=organization_id, resource_type="organization_sso_config", resource_id=config.id,
        after_state={"provider_type": config.provider_type, "issuer": config.issuer, "status": config.status},
        metadata={"provider_type": config.provider_type},
    )
    return config


async def update_sso_config(
    db: Session,
    config: OrganizationSSOConfig,
    actor_user_id: int,
    issuer: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    allowed_domains: list[str] | None = None,
) -> OrganizationSSOConfig:
    """Only touches fields actually supplied (None = leave unchanged), same
    convention as config_service.update_config. Re-runs discovery only if
    issuer actually changes -- a no-op issuer resupply doesn't cost a
    network round trip. Raises SSODiscoveryError before touching the row
    at all if the new issuer fails discovery -- the existing config is
    left exactly as it was, not partially updated.
    """
    before_issuer, before_client_id, before_domains = config.issuer, config.client_id, config.allowed_domains

    if issuer is not None and issuer != config.issuer:
        doc = await verify_oidc_discovery(issuer)
        config.issuer = issuer
        config.authorization_endpoint = doc["authorization_endpoint"]
        config.token_endpoint = doc["token_endpoint"]
        config.userinfo_endpoint = doc.get("userinfo_endpoint")
        config.jwks_uri = doc["jwks_uri"]
        config.last_verified_at = datetime.utcnow()
        config.status = "active"

    if client_id is not None:
        config.client_id = client_id
    if client_secret is not None:
        config.client_secret_encrypted = crypto.encrypt(client_secret)
    if allowed_domains is not None:
        config.allowed_domains = allowed_domains

    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = actor_user_id
    db.commit()
    db.refresh(config)
    # PR11.4b: one event per update call, even when it touches more than
    # one field, mirroring org_service.set_member_roles' identical
    # reasoning -- never client_secret/client_secret_encrypted. Emitted
    # unconditionally (not gated on "did anything actually change") --
    # unlike set_user_status/set_enforced below, update_sso_config has no
    # single before/after value to compare; a no-op resupply is rare
    # enough here not to warrant tracking per-field dirtiness just to
    # suppress it.
    audit_service.log_event(
        db, AuditEventType.SSO_CONFIGURATION_UPDATED, actor_user_id=actor_user_id,
        organization_id=config.organization_id, resource_type="organization_sso_config", resource_id=config.id,
        before_state={"issuer": before_issuer, "client_id": before_client_id, "allowed_domains": before_domains},
        after_state={"issuer": config.issuer, "client_id": config.client_id, "allowed_domains": config.allowed_domains},
        metadata={"provider_type": config.provider_type},
    )
    return config


def delete_sso_config(db: Session, config: OrganizationSSOConfig) -> None:
    db.delete(config)
    db.commit()


def has_completed_sso_login(db: Session, config_id: int) -> bool:
    """True once at least one real user has actually authenticated through
    this config -- an OAuthAccount row with this organization_sso_config_id
    only ever gets created by a *successful* login/link completion
    (create_user_with_oauth / link_oauth_to_existing_user, Phase 2 PR4),
    never by configuring or discovering the IdP alone. This is the lockout
    guard's signal: an org can't enforce SSO until it's been proven to
    actually work for at least one of its members.
    """
    return (
        db.query(OAuthAccount)
        .filter(OAuthAccount.organization_sso_config_id == config_id)
        .first()
        is not None
    )


def set_enforced(
    db: Session, config: OrganizationSSOConfig, enforced: bool, actor_user_id: int
) -> OrganizationSSOConfig:
    """Raises ValueError (-> 400 at the route layer) if turning enforcement
    *on* without the lockout guard being satisfied. Turning it back off is
    always allowed unconditionally -- there's no lockout risk in relaxing
    a restriction, only in adding one.
    """
    if enforced and not config.enforced and not has_completed_sso_login(db, config.id):
        raise ValueError(
            "cannot enforce SSO for this organization until at least one member has "
            "completed a successful SSO login"
        )

    before_enforced = config.enforced
    config.enforced = enforced
    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = actor_user_id
    db.commit()
    db.refresh(config)
    # PR11.4b: only emitted on an actual flip -- a resubmission of the
    # same value (enforced=False -> False) is a no-op the caller already
    # allows unconditionally, but isn't a real enforcement change worth
    # a ledger entry.
    if before_enforced != enforced:
        audit_service.log_event(
            db, AuditEventType.SSO_ENFORCEMENT_CHANGED, actor_user_id=actor_user_id,
            organization_id=config.organization_id, resource_type="organization_sso_config", resource_id=config.id,
            before_state={"enforced": before_enforced}, after_state={"enforced": enforced},
            metadata={"enforced_before": before_enforced, "enforced_after": enforced},
        )
    return config


def set_sso_override(
    db: Session, config: OrganizationSSOConfig, reason: str, actor_user_id: int
) -> OrganizationSSOConfig:
    """Global-admin break-glass bypass: suspends the *effect* of
    `enforced` for this org without changing `enforced` itself, so the
    org's own configuration is preserved and resumes automatically once
    the override is cleared. Deliberately overwrites any prior override
    (re-triggering it just updates who/why/when, not an error) --
    idempotent from the caller's perspective."""
    config.sso_override_at = datetime.utcnow()
    config.sso_override_reason = reason
    config.sso_override_by_user_id = actor_user_id
    db.commit()
    db.refresh(config)
    return config


def clear_sso_override(db: Session, config: OrganizationSSOConfig) -> OrganizationSSOConfig:
    config.sso_override_at = None
    config.sso_override_reason = None
    config.sso_override_by_user_id = None
    db.commit()
    db.refresh(config)
    return config
