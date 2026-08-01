from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.jwt import decode_token
from app.db.session import get_db
from app.db.models import OrganizationMembership

security = HTTPBearer()


def get_current_user(token=Depends(security)):
    try:
        return decode_token(token.credentials)
    except:
        raise HTTPException(401, "Invalid token")


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