"""PR8 (Enterprise IAM Foundation): identity projection -- constructs the
full "who is this user, what can they do" view shared by GET /me and
GET /platform/users/{user_id}/identity (routes_identity.py). Single source
of truth so neither route -- nor any downstream service consuming this
API after validating a JWT -- needs to reconstruct roles/permissions
independently.

Pure read: nothing here ever commits or mutates. Global permissions reuse
the exact set computation build_user_claims (auth_service.py) already uses
for JWT claims, so a user's /me response can never disagree with what
their own token actually grants. Per-organization effective permissions
reuse org_service.permissions_for_membership unchanged (PR7's own
contract) -- not re-derived here.
"""
from sqlalchemy.orm import Session, selectinload

from app.db.models import OrganizationMembership, User
from app.services import org_service


def build_identity(db: Session, user: User) -> dict:
    """Returns a plain dict already shaped to match schemas.identity
    .IdentityOut field-for-field (minus permission expansion, which is the
    route layer's job -- see routes_identity.py's own _permission_out_or_500,
    mirroring the registry-lookup pattern PR6/PR7 already established).
    `user.roles` must already be loaded (see get_identity_for_user_id)."""
    global_permissions = sorted({p.name for r in user.roles for p in r.permissions})
    global_roles = [
        {"id": r.id, "name": r.name, "description": r.description}
        for r in sorted(user.roles, key=lambda r: r.name)
    ]

    memberships = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.user_id == user.id)
        .all()
    )
    organizations = [
        {
            "organization_id": m.organization_id,
            "organization_name": m.organization.name,
            "roles": sorted(r.name for r in m.roles),
            "effective_permissions": sorted(org_service.permissions_for_membership(m)),
        }
        for m in sorted(memberships, key=lambda m: m.organization_id)
    ]

    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "status": user.status,
            "created_at": user.created_at,
        },
        "global_roles": global_roles,
        "global_permissions": global_permissions,
        "organizations": organizations,
    }


def get_identity_for_user_id(db: Session, user_id: int) -> dict | None:
    """None if no such user -- callers (both routes) map that to a 404."""
    user = db.query(User).options(selectinload(User.roles)).filter(User.id == user_id).first()
    if user is None:
        return None
    return build_identity(db, user)
