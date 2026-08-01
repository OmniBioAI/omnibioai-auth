import ipaddress
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import settings
from app.db.models import OrganizationSSOConfig

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
    return config


def delete_sso_config(db: Session, config: OrganizationSSOConfig) -> None:
    db.delete(config)
    db.commit()
