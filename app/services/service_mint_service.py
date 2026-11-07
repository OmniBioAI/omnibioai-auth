"""#443: lets a trusted internal service (svc-bio-agent, holding
service_token.mint) mint a short-lived access token on behalf of an
already-authenticated user of that service, so the real user's identity
-- not the service's own shared identity -- reaches a downstream system
that only accepts an omnibioai-auth JWT (e.g. TES, via api-gateway).

Deliberately lightweight, not a call to auth_service.generate_tokens:
this is not a login. No RefreshToken row, no UserSession row, no
users.last_login_at write, no session-eviction accounting touched --
calling generate_tokens here would manufacture a persisted "session" for
every mint (bio_agent may mint far more often than a human logs in), and
would misrepresent a token-mint as this user having just authenticated.
Reuses exactly the two pieces of generate_tokens that a login-shaped
token issuance and a lightweight one both need: build_user_claims (the
single source of truth for what goes in the payload) and
create_access_token (the actual signing).

#96: the caller's assertion of who the user is is still trusted, so the
endpoint limits what that assertion can reach:
- only existing, active users (no account is ever created here);
- only an org the user is an active member of, in an active org;
- never a user whose token would carry a privileged permission, unless
  the caller also holds service_token.mint_privileged;
- a short token lifetime, and an audit event for every outcome.
"""
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.jwt import create_access_token
from app.core.permission_names import REGISTRY, PermissionScope
from app.db.models import OrganizationMembership
from app.services import audit_service, oauth_service, org_service
from app.services.audit_service import AuditEventType
from app.services.auth_service import build_user_claims

MINT_PRIVILEGED_PERMISSION = "service_token.mint_privileged"

# BOTH-scoped permissions that still belong to service identities, not to
# people. Everything GLOBAL- or ORG-scoped is privileged by scope.
_SERVICE_IDENTITY_PERMISSIONS = frozenset({
    "toolserver.delegate", "toolserver.register", "identity.verify", "delegation.verify",
})


class MintRefused(Exception):
    """The request was refused. `reason` goes to the audit trail only; the
    caller always gets the same response."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def is_privileged_permission(name: str) -> bool:
    """Unknown names count as privileged, so a permission added later is
    refused until someone decides otherwise."""
    entry = REGISTRY.get(name)
    if entry is None:
        return True
    return entry.scope in (PermissionScope.GLOBAL, PermissionScope.ORG) or name in _SERVICE_IDENTITY_PERMISSIONS


def mint_ttl_seconds() -> int:
    return min(settings.SERVICE_MINT_TOKEN_TTL_SECONDS, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


def log_denied(db, actor_user_id: int, reason: str, *, target_email: str, requested_org_id,
               verification_method, target_user_id=None, organization_id=None) -> None:
    audit_service.log_event(
        db, AuditEventType.SERVICE_TOKEN_MINT_DENIED, actor_user_id=actor_user_id,
        target_user_id=target_user_id, organization_id=organization_id,
        resource_type="user", resource_id=target_user_id,
        metadata={
            "reason": reason,
            "target_email": target_email,
            "requested_org_id": requested_org_id,
            "verification_method": verification_method,
        },
    )


def _resolve_membership(db, user_id: int, org_id: int | None):
    if org_id is None:
        return org_service.resolve_primary_membership(db, user_id)
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.status == "active",
        )
        .first()
    )
    if membership is None:
        raise MintRefused("not_a_member")
    return membership


def mint_user_service_token(
    db, target_email: str, actor_user_id: int, *, verification_method: str,
    org_id: int | None = None, allow_privileged: bool = False,
):
    """Mints a token carrying `target_email`'s own permissions for `org_id`
    (or their primary org when omitted). Raises MintRefused, after writing
    a SERVICE_TOKEN_MINT_DENIED audit event, when the request is refused.

    Returns (access_token, expires_in_seconds).
    """
    user = None
    membership = None
    try:
        user = oauth_service.find_user_by_email(db, target_email)
        if user is None:
            raise MintRefused("unknown_user")
        if user.status != "active":
            raise MintRefused("inactive_user")
        membership = _resolve_membership(db, user.id, org_id)
        if membership is not None and membership.organization.status != "active":
            raise MintRefused("organization_inactive")

        payload = build_user_claims(db, user, auth_method="service_mint", membership=membership)
        privileged = [p for p in payload["permissions"] if is_privileged_permission(p)]
        if privileged and not allow_privileged:
            raise MintRefused("privileged_target")
    except MintRefused as refused:
        log_denied(
            db, actor_user_id, refused.reason, target_email=target_email,
            requested_org_id=org_id, verification_method=verification_method,
            target_user_id=user.id if user is not None else None,
            organization_id=membership.organization_id if membership is not None else None,
        )
        raise

    expires_in = mint_ttl_seconds()
    access_token = create_access_token(payload, expires_seconds=expires_in)

    audit_service.log_event(
        db, AuditEventType.SERVICE_TOKEN_MINTED, actor_user_id=actor_user_id,
        target_user_id=user.id, organization_id=payload["org_id"],
        resource_type="user", resource_id=user.id,
        metadata={
            "target_email": target_email,
            "requested_org_id": org_id,
            "organization_id": payload["org_id"],
            "verification_method": verification_method,
            "privileged": bool(privileged),
            # The token's id, for correlation and revocation; never the token.
            "jti": jose_jwt.get_unverified_claims(access_token)["jti"],
        },
    )

    return access_token, expires_in
