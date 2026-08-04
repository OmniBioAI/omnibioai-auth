"""PR8 (Enterprise IAM Foundation): GET /me and
GET /platform/users/{user_id}/identity -- the canonical identity +
effective-authorization projection downstream OmniBioAI services (Control
Center, Studio, LIMS, Marketplace, Billing, Workflow Engine, future Admin
UI) are meant to consume after validating a JWT, instead of each
reconstructing roles/permissions independently. Read-only: no
authentication/JWT/SSO change, nothing here ever mutates.

Both routes share one implementation end to end -- identity_service
.get_identity_for_user_id builds the projection, the two small helpers
below shape it into a response -- and differ only in *whose* identity
(caller's own vs. a path-specified user_id) and *which* authorization gate
runs first (any authenticated user vs. require_permission(MANAGE_ALL_ORGS),
the same permission every other /platform/* route already uses). No new
permission is introduced.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, get_current_user, require_permission
from app.schemas.identity import CurrentUserOut, GlobalRoleOut, IdentityOut, OrganizationIdentityOut
from app.schemas.permissions import PermissionOut
from app.services import identity_service

router = APIRouter(tags=["identity"])


def _permission_out_or_500(name: str) -> PermissionOut:
    """Strict lookup, mirroring routes_platform_roles.py/
    routes_organization_roles.py's own _permission_out_or_500: both /me
    and the platform identity lookup are single-subject detail views (not
    a bulk listing of unrelated targets), so registry/database drift here
    gets the same loud, hard failure those endpoints already use -- not
    the lenient log-and-omit variant PR6/PR7 reserve for bulk listings."""
    perm = REGISTRY.get(name)
    if perm is None:
        raise HTTPException(
            500,
            f"Registry drift: permission {name!r} exists on this identity's roles in "
            "the database but is not present in the Permission Registry.",
        )
    return PermissionOut(**perm.as_dict())


def _identity_out(identity: dict) -> IdentityOut:
    return IdentityOut(
        user=CurrentUserOut(**identity["user"]),
        global_roles=[GlobalRoleOut(**r) for r in identity["global_roles"]],
        global_permissions=identity["global_permissions"],
        organizations=[OrganizationIdentityOut(**o) for o in identity["organizations"]],
    )


def _identity_out_expanded(identity: dict) -> dict:
    """expand_permissions=true variant: global_permissions and each
    organization's effective_permissions become full PermissionOut
    metadata instead of bare names. Returned via JSONResponse, bypassing
    this route's declared response_model entirely -- the same technique
    routes_platform_roles.py's expand_permissions branch already uses --
    so the default (false) path above keeps its original, unmodified
    response_model validation with zero risk of this branch reshaping it.

    `user`/`global_roles` are still routed through their own Pydantic
    schemas (mode="json") here even though their shape doesn't change --
    JSONResponse's plain json.dumps has no datetime support, unlike the
    default path's automatic response_model serialization, so skipping
    this would crash on CurrentUserOut.created_at."""
    return {
        "user": CurrentUserOut(**identity["user"]).model_dump(mode="json"),
        "global_roles": [GlobalRoleOut(**r).model_dump(mode="json") for r in identity["global_roles"]],
        "global_permissions": [
            _permission_out_or_500(n).model_dump(mode="json") for n in identity["global_permissions"]
        ],
        "organizations": [
            {
                "organization_id": o["organization_id"],
                "organization_name": o["organization_name"],
                "roles": o["roles"],
                "effective_permissions": [
                    _permission_out_or_500(n).model_dump(mode="json") for n in o["effective_permissions"]
                ],
            }
            for o in identity["organizations"]
        ],
    }


def _identity_response(identity: dict, expand_permissions: bool):
    if expand_permissions:
        return JSONResponse(_identity_out_expanded(identity))
    return _identity_out(identity)


@router.get("/me", response_model=IdentityOut)
def get_my_identity(
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    identity = identity_service.get_identity_for_user_id(db, int(user["sub"]))
    if identity is None:
        raise HTTPException(404, "User not found")
    return _identity_response(identity, expand_permissions)


@router.get("/platform/users/{user_id}/identity", response_model=IdentityOut)
def get_platform_user_identity(
    user_id: int,
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    caller=Depends(require_permission(MANAGE_ALL_ORGS)),
):
    identity = identity_service.get_identity_for_user_id(db, user_id)
    if identity is None:
        raise HTTPException(404, "User not found")
    return _identity_response(identity, expand_permissions)
