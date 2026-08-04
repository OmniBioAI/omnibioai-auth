"""PR9 (Enterprise IAM Foundation): GET /service/me and
GET /platform/services/{client_id} -- the service-identity counterpart to
PR8's routes_identity.py, unifying machine (client_credentials) and human
(JWT) authorization under the same Permission Registry vocabulary. Both
routes return schemas.service_identity.ServiceIdentityOut and differ only
in which identity (the caller's own service token vs. a path-specified
client_id) and which authorization gate runs first -- exactly the same
"one shared service-layer implementation, thin routes" shape PR8
established.

Authorization is strictly separated by token type, both directions:
- GET /service/me requires a client_credentials token
  (rbac.require_service_identity) -- a human user JWT is rejected exactly
  as require_service_scope already rejects one for other service routes.
- GET /me (PR8, untouched) already rejects a client_credentials token via
  get_current_user's existing Phase 2 PR1 check -- a service token still
  can never satisfy it.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, require_permission, require_service_identity
from app.schemas.permissions import PermissionOut
from app.schemas.service_identity import ServiceIdentityOut
from app.services import service_identity

router = APIRouter(tags=["service-identity"])


def _permission_out_or_500(name: str) -> PermissionOut:
    """Strict lookup, mirroring routes_identity.py's own
    _permission_out_or_500: both routes below are single-subject detail
    views (one specific service identity), not a bulk listing, so
    registry/database drift 500s loudly here -- same rule PR6/PR7/PR8
    already established for detail endpoints."""
    perm = REGISTRY.get(name)
    if perm is None:
        raise HTTPException(
            500,
            f"Registry drift: permission {name!r} exists on this service identity's scopes "
            "in the database but is not present in the Permission Registry.",
        )
    return PermissionOut(**perm.as_dict())


def _identity_response(identity: dict, expand_permissions: bool):
    if not expand_permissions:
        return ServiceIdentityOut(**identity)
    # expand_permissions=true: bypasses this route's declared
    # response_model via JSONResponse, the same technique
    # routes_identity.py's own expanded branch uses -- created_at must be
    # routed through the schema's own serialization (mode="json") here
    # too, for the identical datetime reason PR8 hit and fixed.
    base = ServiceIdentityOut(**identity).model_dump(mode="json")
    base["permissions"] = [_permission_out_or_500(n).model_dump(mode="json") for n in identity["permissions"]]
    return JSONResponse(base)


@router.get("/service/me", response_model=ServiceIdentityOut)
def get_my_service_identity(
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    payload: dict = Depends(require_service_identity()),
):
    identity = service_identity.identity_from_token_payload(db, payload)
    if identity is None:
        raise HTTPException(403, "Forbidden -- service identity is inactive or no longer exists")
    return _identity_response(identity, expand_permissions)


@router.get("/platform/services/{client_id}", response_model=ServiceIdentityOut)
def get_platform_service_identity(
    client_id: str,
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    caller=Depends(require_permission(MANAGE_ALL_ORGS)),
):
    identity = service_identity.identity_for_client_id(db, client_id)
    if identity is None:
        raise HTTPException(404, "Service identity not found")
    return _identity_response(identity, expand_permissions)
