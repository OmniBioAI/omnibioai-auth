from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.jwt import decode_token
from app.core.token_revocation import assert_token_usable
from app.db.session import get_db
from app.db.models import Organization, OrganizationMembership
from app.services import org_service, role_service

security = HTTPBearer()


def get_current_user(token=Depends(security), db: Session = Depends(get_db)):
    try:
        payload = decode_token(token.credentials)
    except:
        raise HTTPException(401, "Invalid token")

    # PR0.1: previously this dependency checked only signature/expiry, so
    # logout/revocation/suspension had no effect on any direct caller of
    # this service -- only on callers going through /auth/validate's
    # remote-validation path. assert_token_usable centralizes the same
    # blacklist/revoked_tokens/status checks /auth/validate already did,
    # so both paths now enforce the same guarantees.
    assert_token_usable(payload, db)

    # Phase 2 PR1: a client_credentials token (app/core/jwt.py's
    # create_service_access_token) has no sub/email at all -- it's a
    # service identity, not a user. Rejecting it here, once, in the shared
    # dependency every user-identity route already depends on, is what
    # makes "service tokens can never satisfy a user-identity check" true
    # everywhere (e.g. routes_license.py's `int(user["sub"])`), rather than
    # relying on every individual route to remember to check auth_method
    # itself.
    if payload.get("auth_method") == "client_credentials":
        raise HTTPException(401, "Invalid token")
    return payload


def require_role(role: str):
    def wrapper(user=Depends(get_current_user)):
        if role not in user.get("roles", []):
            raise HTTPException(403, "Forbidden")
        return user
    return wrapper


def require_permission(permission: str):
    def wrapper(user=Depends(get_current_user)):
        perms = user.get("permissions", [])
        if permission not in perms:
            raise HTTPException(403, "Forbidden")
        return user
    return wrapper


# ---------------------------------------------------------------------------
# Org-scoped authorization (Phase 1 PR2). Deliberately separate from
# require_permission above: that one trusts the `permissions` claim baked
# into the JWT at login time (global roles only, computed once at login).
# Org membership/roles are new and not yet represented in the JWT at all
# (that cutover -- JWT v2 with an org_id claim -- is Phase 1 PR3, not this
# change), so authorization here has to hit the database live on every
# request instead. `org_id` is resolved from the request path automatically
# by FastAPI's dependency injection, matching whatever path parameter name
# the calling route declares.
# ---------------------------------------------------------------------------


def get_org_membership(
    org_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
) -> OrganizationMembership:
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == int(user["sub"]),
            OrganizationMembership.status == "active",
        )
        .first()
    )
    if not membership:
        # 404, not 403 -- do not confirm to a non-member whether an org_id
        # exists at all.
        raise HTTPException(404, "Organization not found")
    return membership


def require_org_permission(permission: str):
    def wrapper(membership: OrganizationMembership = Depends(get_org_membership)):
        perms = {p.name for role in membership.roles for p in role.permissions}
        if permission not in perms:
            raise HTTPException(403, "Forbidden")
        return membership
    return wrapper


# ---------------------------------------------------------------------------
# Platform-admin cross-tenant bypass (Phase 3 PR0.4). Checks a distinct,
# narrowly-named global permission -- `manage_all_orgs` -- never the role
# name "platform_admin" itself, mirroring Phase 2 PR5's
# override_sso_enforcement precedent: the role is simply "whatever holds
# this permission today," not something authorization code hardcodes.
#
# This does not replace get_org_membership/require_org_permission for
# anyone lacking the permission -- it adds exactly one new way to satisfy
# the same check, falling through to the *exact*, unmodified functions
# above for every other caller. No existing route's behavior changes for
# a non-platform-admin caller.
# ---------------------------------------------------------------------------

MANAGE_ALL_ORGS = "manage_all_orgs"


def _platform_admin_membership(
    db: Session, org_id: int, user: dict
) -> OrganizationMembership | None:
    """A synthetic, never-persisted OrganizationMembership granting a
    platform admin the same effective org-scoped permissions a real
    org_admin of this org would have (reuses the actual, shared
    `org_admin` Role row -- see org_service.ORG_ADMIN_ROLE -- rather than
    fabricating a parallel permission set that could drift from it).
    Never `db.add()`-ed or committed: a platform admin visiting an org
    they don't belong to must leave zero trace in
    `organization_memberships` and never appear in that org's real member
    list.

    Returns None -- fail closed -- if the org doesn't exist or the
    org_admin Role catalog entry hasn't been created yet in this
    environment (no org has ever been created). Either case falls through
    to the real membership check in the caller below, never granting
    access on an incomplete resolution.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        return None

    admin_role = role_service.get_role_by_name(db, org_service.ORG_ADMIN_ROLE)
    if admin_role is None:
        return None

    membership = OrganizationMembership(
        organization_id=org_id,
        user_id=int(user["sub"]),
        status="active",
        roles=[admin_role],
    )
    membership.organization = org
    return membership


def get_org_membership_or_platform_admin(
    org_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> OrganizationMembership:
    """Platform-admin-aware drop-in replacement for get_org_membership.

    Built entirely on get_current_user's already-decoded, already-checked
    payload -- no second JWT decode, and the client_credentials rejection
    get_current_user already performs applies here for free (a service
    token can never reach this function with a usable payload at all).
    The `auth_method` check below is a redundant, defense-in-depth
    restatement of that same guarantee, not a new mechanism -- it must
    hold even if some future change to get_current_user's internal
    ordering were to loosen it.

    Fails closed: any problem resolving the bypass (permission absent,
    org missing, unexpected exception) falls through to the exact,
    unmodified get_org_membership call below rather than granting access.
    """
    try:
        if (
            user.get("auth_method") != "client_credentials"
            and MANAGE_ALL_ORGS in (user.get("permissions") or [])
        ):
            synthetic = _platform_admin_membership(db, org_id, user)
            if synthetic is not None:
                return synthetic
    except Exception:
        pass

    return get_org_membership(org_id=org_id, db=db, user=user)


def require_org_permission_or_platform_admin(permission: str):
    """Platform-admin-aware drop-in replacement for require_org_permission.
    Identical permission check to require_org_permission's own wrapper --
    the only thing that differs is where `membership` comes from -- so a
    platform admin must hold the same named permission
    (manage_org/manage_teams/manage_api_keys/manage_oauth_clients/
    manage_sso) via their synthetic org_admin role that a real org_admin
    would need, rather than bypassing the permission check itself.
    """
    def wrapper(
        membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
    ):
        perms = {p.name for role in membership.roles for p in role.permissions}
        if permission not in perms:
            raise HTTPException(403, "Forbidden")
        return membership
    return wrapper


# ---------------------------------------------------------------------------
# Service-to-service authorization (Phase 2 PR1). Deliberately separate from
# get_current_user/require_permission/require_org_permission above: a
# client_credentials token has no `sub`/`email` claim at all (it's a service
# identity, not a user -- see app/core/jwt.py's create_service_access_token),
# so any of those existing dependencies would either reject it outright or,
# worse, crash on `int(user["sub"])` deep inside a handler that assumed a
# user token. Routes meant to accept service tokens must depend on this and
# only this -- never get_current_user -- so a service token can never
# silently satisfy a user-identity check, and a user token can never
# satisfy a scope check meant for services.
# ---------------------------------------------------------------------------


def require_service_scope(scope: str):
    def wrapper(token=Depends(security)):
        try:
            payload = decode_token(token.credentials)
        except Exception:
            raise HTTPException(401, "Invalid token")
        if payload.get("auth_method") != "client_credentials":
            raise HTTPException(403, "Forbidden -- service token required")
        if scope not in payload.get("scopes", []):
            raise HTTPException(403, "Forbidden")
        return payload
    return wrapper


def require_service_identity():
    """PR9: authenticates a client_credentials service token without
    requiring any specific scope -- unlike require_service_scope above,
    this backs GET /service/me, where a service just needs to *be* a
    valid service identity to read its own identity/permissions, not
    already hold a particular one. Purely additive: does not change
    require_service_scope, get_current_user, or any other existing
    function's behavior -- a user token is still rejected here exactly as
    require_service_scope already rejects one, and get_current_user's own
    client_credentials rejection (Phase 2 PR1) is untouched, so a service
    token still can never satisfy /me."""
    def wrapper(token=Depends(security)):
        try:
            payload = decode_token(token.credentials)
        except Exception:
            raise HTTPException(401, "Invalid token")
        if payload.get("auth_method") != "client_credentials":
            raise HTTPException(403, "Forbidden -- service token required")
        return payload
    return wrapper