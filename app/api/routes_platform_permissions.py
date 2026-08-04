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
from fastapi import APIRouter, Depends, Query

from app.core.permission_names import (
    PermissionCategory,
    PermissionScope,
    filter_registry,
    registry_stats,
)
from app.rbac import MANAGE_ALL_ORGS, require_permission
from app.schemas.permissions import PermissionOut, PermissionStatsOut

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
def list_permissions(
    category: PermissionCategory | None = Query(None),
    scope: PermissionScope | None = Query(None),
    legacy: bool | None = Query(None),
    deprecated: bool | None = Query(None),
    search: str | None = Query(None),
    user=Depends(_require_platform_admin),
):
    # PR6: all filters default to None, which is a no-op in filter_registry
    # -- identical output to PR5's unfiltered list_registry() call when no
    # query parameters are given, so the default response is unchanged.
    # Filtering happens entirely in memory; the registry stays the sole
    # source of truth, never re-derived or hand-mapped.
    perms = filter_registry(
        category=category, scope=scope, legacy=legacy, deprecated=deprecated, search=search,
    )
    return [PermissionOut(**perm.as_dict()) for perm in perms]


@router.get("/permissions/stats", response_model=PermissionStatsOut)
def permission_registry_stats(user=Depends(_require_platform_admin)):
    # registry_stats() is a pure in-memory computation over REGISTRY --
    # no database access, matching list_registry()'s own contract.
    return PermissionStatsOut(**registry_stats())
