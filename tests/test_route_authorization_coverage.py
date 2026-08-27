"""Phase 3 PR0.3: automated protection against a route that should be
org-permission-gated accidentally shipping with only bare get_current_user
(or nothing) checking it -- the "forgotten endpoint protection" risk named
in ~/phase3_security_review.md sections 2 and 3. This walks the app's own
FastAPI route table and dependency graph directly, so it fails the moment
a *future* route is added under an org-scoped path without a real
authorization dependency, rather than relying on a reviewer to notice.

Not a test of any specific route's business logic -- see
test_idor_org_scoping.py for that. This only asks: "does this route's
dependency chain contain something more specific than 'is this a valid
token'?"
"""
from app.main import app

# Qualnames of dependencies that genuinely check *something* beyond bare
# identity. get_org_membership/require_org_permission and their Phase 3
# PR0.4 platform-admin-aware counterparts (get_org_membership_or_
# platform_admin/require_org_permission_or_platform_admin) all check real
# org membership/permission (app/rbac.py) -- every org-scoped route was
# migrated to the *_or_platform_admin variants by PR0.4, but the plain
# versions are kept here too since they remain legitimate for any future
# route that deliberately must never allow the cross-tenant bypass.
# require_permission's and require_role's wrappers check the JWT's global
# permissions/roles claim -- the deliberate pattern routes_org_sso.py's
# (and, since #67, routes_org_saml.py's) break-glass override endpoints
# use instead of org membership (Phase 2 PR5: it must work even when the
# org's own admin is the one locked out), so they count as "protected"
# too, not as a gap.
ORG_MEMBERSHIP_QUALNAMES = {
    "get_org_membership",
    "require_org_permission.<locals>.wrapper",
    "get_org_membership_or_platform_admin",
    "require_org_permission_or_platform_admin.<locals>.wrapper",
}
GLOBAL_PERMISSION_QUALNAMES = {
    "require_permission.<locals>.wrapper",
    "require_role.<locals>.wrapper",
}
AUTHORIZED_QUALNAMES = ORG_MEMBERSHIP_QUALNAMES | GLOBAL_PERMISSION_QUALNAMES


def _dependency_qualnames(dependant) -> set[str]:
    """Every dependency callable's __qualname__ anywhere in this route's
    full dependency tree, recursively -- not just its immediate Depends()
    list. get_current_user itself always appears somewhere (every
    org-scoped dependency is built on top of it), so its presence alone
    proves nothing; what matters is whether anything *more specific* also
    appears.
    """
    names = set()
    if dependant.call is not None:
        names.add(getattr(dependant.call, "__qualname__", ""))
    for sub in dependant.dependencies:
        names |= _dependency_qualnames(sub)
    return names


def _org_scoped_routes():
    """Every registered route whose path is scoped under the org-
    membership surface (routes_orgs.py's `/orgs` prefix and everything
    nested under it: teams, api-keys, oauth-clients, org-sso) -- the
    class of route this check cares about. Extend this tuple if a future
    router introduces a differently-named org-scoping path param.

    Requires the `/orgs` prefix *and* an `{org_id}` path segment,
    deliberately -- Phase 3 PR1's `/platform/orgs/{org_id}` also has
    `{org_id}` in its path (it identifies which org to show, the same as
    every route here), but it is a platform-wide, non-org-membership
    route gated by require_permission(MANAGE_ALL_ORGS) alone (see
    routes_platform_admin.py) -- a bare `"{org_id}" in path` substring
    check would incorrectly sweep it into this scan.
    """
    for route in app.routes:
        path = getattr(route, "path", "")
        if path.startswith("/orgs") and "{org_id}" in path:
            yield route


def test_every_org_scoped_route_has_a_real_authorization_dependency():
    unprotected = []
    for route in _org_scoped_routes():
        qualnames = _dependency_qualnames(route.dependant)
        if qualnames & AUTHORIZED_QUALNAMES:
            continue
        unprotected.append((sorted(route.methods or []), route.path))

    assert not unprotected, (
        "Org-scoped route(s) with no authorization dependency beyond bare "
        "get_current_user (or none at all) -- every route under an "
        "{org_id} path must depend on get_org_membership, "
        "require_org_permission(...), or (for a deliberate global-admin "
        "exception like the SSO break-glass override) require_permission(...)"
        f"/require_role(...): {unprotected}"
    )


def test_org_scoped_route_inventory_matches_expected_count():
    """A secondary tripwire: if this number changes, a route was added or
    removed under an {org_id} path -- worth a deliberate look at the diff
    that changed it, not just a silent pass/fail on the check above. Not a
    substitute for the authorization check itself, since a route could in
    principle be added *and* correctly protected, changing this count for
    a completely benign reason -- this just makes route-surface growth
    visible rather than silent.

    21 -> 25 as of Phase 3 PR3B: GET /orgs/{org_id}/roles, GET/POST
    /orgs/{org_id}/members/{user_id}/roles, and DELETE
    /orgs/{org_id}/members/{user_id}/roles/{role_id} were added, all using
    require_org_permission_or_platform_admin(MANAGE_ORG) -- the same
    dependency update_member_roles (the pre-existing PUT at the same path)
    already used, so this is the deliberate, reviewed reason for the
    count's change, not a silent gap.

    25 -> 30 as of PR11.5.5 (Enterprise Organization MFA Policy): POST/GET/
    PATCH /orgs/{org_id}/mfa-policy (require_org_permission_or_platform_admin(
    MANAGE_SSO), mirroring the existing SSO config CRUD exactly) and POST/
    DELETE /orgs/{org_id}/mfa-policy/override (require_permission(
    MANAGE_ALL_ORGS), the same global-permission break-glass shape the SSO
    override routes already use) -- see
    docs/pr11-mfa-org-policy-discovery.md SS9.

    30 -> 37 as of Team Management v0.8.0 Step 3/6 (commit 5378a2d, "add
    per-member route endpoints"): the 7 new per-member endpoints under
    `/orgs/{org_id}/teams/{team_id}/...` -- GET/PATCH {team_id}, GET
    {team_id}/members, POST {team_id}/invite, PUT {team_id}/members/
    {user_id}/role, DELETE {team_id}/members/{user_id}, POST {team_id}/
    leave. (POST/GET /teams and PUT/DELETE {team_id} predate this and
    were already counted in the prior 30.) Every one of the 7 uses
    get_org_membership_or_platform_admin (GET endpoints, or as the base
    membership check the mutating ones inline-verify manage_teams/team-
    admin on top of) -- test_every_org_scoped_route_has_a_real_
    authorization_dependency above already passes for all of them; this
    is purely the count catching up to routes that were already
    correctly protected when they shipped.

    37 -> 41 as of PR8 (SAML Organization Configuration CRUD): POST/GET/
    PATCH/DELETE /orgs/{org_id}/saml, all using require_org_permission_
    or_platform_admin(MANAGE_SSO) -- reuses the existing manage_sso
    permission rather than a new manage_saml (same precedent PR11.5.5's
    MFA policy routes already set for reusing manage_sso beyond its
    original OIDC-only name). Still 41 as of #263 (per-org SAML
    enforcement) -- OrganizationSAMLConfig gained an `enforced`-style
    flag with a lockout guard (mirroring OrganizationSSOConfig/
    OrganizationMFAPolicy), applied through this same existing PATCH
    route, not a new one.

    41 -> 43 as of #67 (SAML break-glass override): POST/DELETE
    /orgs/{org_id}/saml/override, reusing require_permission(
    OVERRIDE_SSO_ENFORCEMENT) verbatim -- not a new SAML-specific
    permission -- same break-glass reasoning as the SSO/MFA-policy
    override routes (must work even if the org's own admin is locked
    out). #263's own note above ("no break-glass override route added
    for it... a deliberate, disclosed scope boundary") was reassessed:
    the lockout risk turned out to be identical in shape to OIDC's, not
    genuinely lower, so this closes that gap rather than leaving it
    open. See app/api/routes_org_saml.py's own module docstring for why
    the permission/schema are shared while the audit events
    (SAML_OVERRIDE_CREATED/REMOVED) stay provider-specific. This is now
    a third entry in the global-permission-exception set
    test_sso_mfa_policy_and_saml_override_routes_are_the_only_global_
    permission_exception locks in below.
    """
    assert len(list(_org_scoped_routes())) == 43


def test_every_org_scoped_route_uses_the_platform_admin_aware_dependency():
    """Stricter than test_every_org_scoped_route_has_a_real_authorization_
    dependency above: that check accepts the plain get_org_membership/
    require_org_permission too, so it would NOT catch a route that was
    supposed to be migrated to the *_or_platform_admin variant (Phase 3
    PR0.4) but was accidentally missed -- the plain dependency still
    counts as "a real authorization dependency" there. This test closes
    that specific gap: every org-membership-checked route (i.e. every one
    of the 21 except the 2 deliberate global-permission SSO-override
    routes) must use get_org_membership_or_platform_admin or
    require_org_permission_or_platform_admin.<locals>.wrapper specifically.
    """
    platform_admin_aware = {
        "get_org_membership_or_platform_admin",
        "require_org_permission_or_platform_admin.<locals>.wrapper",
    }
    not_migrated = []
    for route in _org_scoped_routes():
        qualnames = _dependency_qualnames(route.dependant)
        if qualnames & GLOBAL_PERMISSION_QUALNAMES:
            continue  # the deliberate SSO-override exception
        if not (qualnames & platform_admin_aware):
            not_migrated.append((sorted(route.methods or []), route.path))

    assert not not_migrated, (
        "Org-scoped route(s) still depending on the plain get_org_membership/"
        "require_org_permission instead of their platform-admin-aware "
        f"replacements: {not_migrated}"
    )


def test_sso_mfa_policy_and_saml_override_routes_are_the_only_global_permission_exception():
    """Locks in *which* routes are allowed to skip org-membership checking
    in favor of a global permission -- so a future route reusing this
    pattern for the wrong reason (convenience, not a genuine break-glass
    need) shows up as a diff to this test, not a silent precedent.

    PR11.5.5 added the second deliberate exception here,
    /orgs/{org_id}/mfa-policy/override -- same break-glass reasoning as
    the SSO override route (must work even if the org's own admin is
    locked out), reusing the existing manage_all_orgs permission rather
    than a new one.

    #67 adds the third: /orgs/{org_id}/saml/override, reusing
    override_sso_enforcement (SSO's own permission) verbatim rather than
    a new SAML-specific one -- see app/api/routes_org_saml.py's module
    docstring for why permissions are deliberately shared across SSO
    mechanisms even though audit events are not.
    """
    global_permission_only = []
    for route in _org_scoped_routes():
        qualnames = _dependency_qualnames(route.dependant)
        if qualnames & ORG_MEMBERSHIP_QUALNAMES:
            continue
        if qualnames & GLOBAL_PERMISSION_QUALNAMES:
            global_permission_only.append(route.path)

    assert set(global_permission_only) == {
        "/orgs/{org_id}/sso/override",
        "/orgs/{org_id}/mfa-policy/override",
        "/orgs/{org_id}/saml/override",
    }
