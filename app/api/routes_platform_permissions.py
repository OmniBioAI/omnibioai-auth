"""PR5 (Enterprise IAM Foundation): read-only exposure of the Permission
Registry (app/core/permission_names.py) built in PR4. Purpose: give future
consumers -- an RBAC admin UI, organization permission assignment UI,
billing/marketplace authorization UIs, audit systems -- a single stable API
to read the registry from, instead of each depending on this repo's Python
module directly.

Metadata only: no enforcement behavior changes, no new permission, no
database access. list_registry() is a pure in-memory read of the module-
level REGISTRY built at import time, so this router needs no `db` session
at all.
"""
from fastapi import APIRouter, Depends

from app.core.permission_names import list_registry
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.permissions import PermissionOut

# Same prefix/tag convention routes_platform_admin.py, routes_platform_
# roles.py, and routes_platform_users.py already established for this
# family of platform-admin-only surfaces.
router = APIRouter(prefix="/platform", tags=["platform-admin"])

# Reuses the existing platform-admin permission (Phase 3 PR0.4) rather than
# introducing a new one (e.g. a "permission.registry.read" name) -- this
# endpoint is platform metadata, gated exactly the way every other
# /platform/* read endpoint already is. No new permission is added to the
# registry for this PR.
_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(user=Depends(_require_platform_admin)):
    # list_registry() already returns entries sorted by name -- passed
    # through as-is via PermissionDef.as_dict(), never re-derived or
    # hand-mapped, so this endpoint can't drift from the registry it wraps.
    return [PermissionOut(**perm.as_dict()) for perm in list_registry()]
