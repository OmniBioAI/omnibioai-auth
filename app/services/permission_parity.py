"""Phase 1 PR3 transition safety net.

Compares the legacy global permission set (user_roles -> role_permissions,
still the thing require_permission actually enforces) against the new
org-scoped permission set (organization_memberships -> membership_roles)
for the same user, every time a token is issued. Purely observational --
it does not change what's enforced anywhere. The point is to catch drift
between the two systems (a bad backfill, a role assigned on one side but
not the other, etc.) by logging it loudly, rather than silently carrying
a wrong org_role claim in tokens until PR4's cutover makes it load-bearing.
"""

import logging

from app.services import role_service

logger = logging.getLogger("omnibioai.auth.permission_parity")


def check_and_log(user, global_permissions: list[str], org_membership) -> dict:
    """Returns the comparison result (also useful for tests asserting on it
    directly), and logs a warning -- never silently drops the difference --
    whenever the two permission sets disagree."""
    org_permissions = role_service.permissions_for_roles(org_membership.roles)
    global_set = set(global_permissions)

    missing_in_org = global_set - org_permissions
    extra_in_org = org_permissions - global_set

    result = {
        "user_id": user.id,
        "org_id": org_membership.organization_id,
        "matches": not missing_in_org and not extra_in_org,
        "missing_in_org": sorted(missing_in_org),
        "extra_in_org": sorted(extra_in_org),
    }

    if not result["matches"]:
        logger.warning(
            "permission_parity_mismatch user_id=%s org_id=%s missing_in_org=%s extra_in_org=%s",
            user.id,
            org_membership.organization_id,
            result["missing_in_org"],
            result["extra_in_org"],
        )

    return result
