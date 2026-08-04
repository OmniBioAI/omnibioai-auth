"""PR3D: named constants for permissions consumed by IAM-backed
authorization checks outside this repo (starting with
omnibioai-control-center's require_iam_permission). Centralizing these
three here, rather than repeating the literal strings at each seed site,
keeps init_admin.py and any future seed/grant call sites from drifting on
spelling. Not yet a full permission registry (that consolidation, across
every existing ad hoc permission string in this file's callers, is
tracked separately) -- scoped to only the three names this PR introduces.

PR4 (Enterprise IAM Foundation): this module now also hosts the Permission
Registry -- the single source of truth for every permission name this repo
knows about, existing and future. It is a pure vocabulary layer: it does not
change what any route enforces, does not touch the `Permission`/`Role`
database schema, and does not seed any new DB rows. See PermissionDef's
docstring below for the stability guarantees a registered name carries.
"""

import re
from dataclasses import dataclass
from enum import Enum

PLATFORM_MANAGE_INFRA = "platform.manage_infra"
PLATFORM_MANAGE_CRON = "platform.manage_cron"
PLATFORM_MANAGE_CONTENT = "platform.manage_content"


class PermissionScope(str, Enum):
    """Where a permission is legal to assign. GLOBAL = checked via
    require_permission against the JWT permissions claim (app/rbac.py).
    ORG = checked live via require_org_permission against an
    OrganizationMembership's roles. BOTH is for permissions that are not
    inherently tied to how today's two legacy mechanisms happen to split --
    reserved for future entries so they aren't permanently pinned to one
    side before an enforcement decision is made."""

    GLOBAL = "global"
    ORG = "org"
    BOTH = "both"


class PermissionCategory(str, Enum):
    """Grouping for a future admin UI. Purely descriptive metadata -- never
    read by any enforcement path."""

    PLATFORM = "platform"
    ORGANIZATION = "organization"
    WORKFLOW = "workflow"
    MODEL = "model"
    DATASET = "dataset"
    BILLING = "billing"
    MARKETPLACE = "marketplace"


@dataclass(frozen=True)
class PermissionDef:
    """One registered permission name.

    `name` is a permanent, versionless API identifier once released: it can
    appear in a deployed JWT `permissions` claim, a persisted
    `Role.permissions` row, or an external consumer's stored authorization
    decision (e.g. omnibioai-control-center's
    require_iam_permission("platform.manage_infra")). It must never be
    renamed and its semantic meaning must never change -- see this repo's
    PR4 design doc for the full stability policy. Evolution is additive
    only: a new capability gets a new entry; a sunsetting one gets
    `deprecated=True` + `deprecated_reason`, never a mutated `name`,
    `resource`, or `action`.
    """

    name: str

    resource: str
    action: str

    scope: PermissionScope
    category: PermissionCategory

    description: str

    legacy: bool = False

    deprecated: bool = False
    deprecated_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "resource": self.resource,
            "action": self.action,
            "scope": self.scope.value,
            "category": self.category.value,
            "description": self.description,
            "legacy": self.legacy,
            "deprecated": self.deprecated,
            "deprecated_reason": self.deprecated_reason,
        }


# ---------------------------------------------------------------------------
# Registry contents.
#
# Legacy entries (legacy=True): every permission name that already exists in
# a deployed database/JWT today. Names are copied verbatim from their call
# sites (app/db/init_admin.py, app/services/org_service.py, and the various
# routes_*.py MANAGE_* constants) -- never reformatted, never renamed.
# `scope` reflects how each one is actually enforced today: GLOBAL for the
# ones gated by require_permission() (checked against the JWT claim), ORG
# for the ones gated by require_org_permission()/
# require_org_permission_or_platform_admin() (checked live against an
# OrganizationMembership's roles).
# ---------------------------------------------------------------------------

REGISTRY: dict[str, PermissionDef] = {}


def _register(perm: PermissionDef) -> None:
    REGISTRY[perm.name] = perm


# --- Platform (global) permissions -- legacy -------------------------------

_register(
    PermissionDef(
        name="manage_roles",
        resource="roles",
        action="manage",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage global roles and their permission assignments.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_licenses",
        resource="licenses",
        action="manage",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage platform license validation and status.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_config",
        resource="config",
        action="manage",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage platform-wide LLM/cloud/directory configuration.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="override_sso_enforcement",
        resource="sso_enforcement",
        action="override",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Break-glass override of an organization's enforced SSO login.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_all_orgs",
        resource="all_orgs",
        action="manage",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Cross-tenant platform-admin access to every organization.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name=PLATFORM_MANAGE_INFRA,
        resource="platform",
        action="manage_infra",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage Control Center's docker/services/summary/config surfaces.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name=PLATFORM_MANAGE_CRON,
        resource="platform",
        action="manage_cron",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage Control Center's scheduled cron jobs.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name=PLATFORM_MANAGE_CONTENT,
        resource="platform",
        action="manage_content",
        scope=PermissionScope.GLOBAL,
        category=PermissionCategory.PLATFORM,
        description="Manage Control Center's known-issues/report/coverage content.",
        legacy=True,
    )
)

# --- Organization-scoped permissions -- legacy ------------------------------

_register(
    PermissionDef(
        name="manage_org",
        resource="org",
        action="manage",
        scope=PermissionScope.ORG,
        category=PermissionCategory.ORGANIZATION,
        description="Manage an organization's own settings and membership.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_teams",
        resource="teams",
        action="manage",
        scope=PermissionScope.ORG,
        category=PermissionCategory.ORGANIZATION,
        description="Manage an organization's teams and their members.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_api_keys",
        resource="api_keys",
        action="manage",
        scope=PermissionScope.ORG,
        category=PermissionCategory.ORGANIZATION,
        description="Manage an organization's API keys.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_oauth_clients",
        resource="oauth_clients",
        action="manage",
        scope=PermissionScope.ORG,
        category=PermissionCategory.ORGANIZATION,
        description="Manage an organization's OAuth2 service-identity clients.",
        legacy=True,
    )
)
_register(
    PermissionDef(
        name="manage_sso",
        resource="sso",
        action="manage",
        scope=PermissionScope.ORG,
        category=PermissionCategory.ORGANIZATION,
        description="Manage an organization's SSO/OIDC identity provider configuration.",
        legacy=True,
    )
)

# --- Future enterprise permissions -- reserved, not yet enforced -----------
# All BOTH-scoped: none of these are inherently global- or org-only, and
# pinning one now would foreclose a legitimate future need (e.g. a
# platform-wide support-staff billing.read alongside a per-org one). No
# route enforces any of these yet.

_register(
    PermissionDef(
        name="workflow.execute",
        resource="workflow",
        action="execute",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.WORKFLOW,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="model.use",
        resource="model",
        action="use",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.MODEL,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="dataset.read",
        resource="dataset",
        action="read",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.DATASET,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="usage.read",
        resource="usage",
        action="read",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.BILLING,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="billing.read",
        resource="billing",
        action="read",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.BILLING,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="billing.manage",
        resource="billing",
        action="manage",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.BILLING,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="subscription.manage",
        resource="subscription",
        action="manage",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.BILLING,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)
_register(
    PermissionDef(
        name="marketplace.install",
        resource="marketplace",
        action="install",
        scope=PermissionScope.BOTH,
        category=PermissionCategory.MARKETPLACE,
        description="Reserved -- not yet enforced by any route.",
        legacy=False,
    )
)


# ---------------------------------------------------------------------------
# Validation helpers.
# ---------------------------------------------------------------------------

_PERMISSION_FORMAT_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")


def is_known_permission(name: str) -> bool:
    """True if `name` is registered -- legacy or not."""
    return name in REGISTRY


def is_valid_permission_format(name: str) -> bool:
    """`resource.action` shape check: lowercase, single-dot-separated,
    non-empty resource/action segments each starting with a letter. Only
    required of new (`legacy=False`) registry entries -- legacy names are
    exempt, since several (e.g. "manage_org") predate this format entirely."""
    return bool(_PERMISSION_FORMAT_RE.match(name))


def list_registry() -> list[PermissionDef]:
    """All registered permissions, sorted by name. Backs the read-only
    `GET /platform/permissions` endpoint (PR5)."""
    return sorted(REGISTRY.values(), key=lambda p: p.name)


def filter_registry(
    category: PermissionCategory | None = None,
    scope: PermissionScope | None = None,
    legacy: bool | None = None,
    deprecated: bool | None = None,
    search: str | None = None,
) -> list[PermissionDef]:
    """PR6: in-memory filtering over the registry -- backs `GET
    /platform/permissions`'s optional query parameters. No database access;
    operates entirely on `list_registry()`'s already-sorted output, so the
    result stays sorted by name. `search` matches case-insensitively
    against both `name` and `description`."""
    results = list_registry()
    if category is not None:
        results = [p for p in results if p.category == category]
    if scope is not None:
        results = [p for p in results if p.scope == scope]
    if legacy is not None:
        results = [p for p in results if p.legacy == legacy]
    if deprecated is not None:
        results = [p for p in results if p.deprecated == deprecated]
    if search:
        needle = search.lower()
        results = [
            p for p in results
            if needle in p.name.lower() or needle in p.description.lower()
        ]
    return results


def registry_stats() -> dict:
    """PR6: aggregate counts over the registry, computed directly from
    REGISTRY -- no database access. Backs `GET /platform/permissions/stats`."""
    all_perms = list(REGISTRY.values())
    by_scope: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for p in all_perms:
        by_scope[p.scope.value] = by_scope.get(p.scope.value, 0) + 1
        by_category[p.category.value] = by_category.get(p.category.value, 0) + 1
    return {
        "total_permissions": len(all_perms),
        "legacy_permissions": sum(1 for p in all_perms if p.legacy),
        "future_permissions": sum(1 for p in all_perms if not p.legacy),
        "by_scope": by_scope,
        "by_category": by_category,
        "deprecated_permissions": sum(1 for p in all_perms if p.deprecated),
    }


# ---------------------------------------------------------------------------
# Registry invariant: every non-legacy entry must satisfy the resource.action
# format. Enforced at import time (not per-request) so a future entry added
# without following the format fails immediately, not silently.
# ---------------------------------------------------------------------------

for _perm in REGISTRY.values():
    if not _perm.legacy and not is_valid_permission_format(_perm.name):
        raise ValueError(
            f"Registry entry {_perm.name!r} is not legacy and does not "
            "satisfy resource.action format"
        )
del _perm
