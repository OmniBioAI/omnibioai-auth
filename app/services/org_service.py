from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import Organization, OrganizationMembership, User
from app.services import audit_service, role_service
from app.services.audit_service import AuditEventType

# Reused across every organization -- Role/Permission remain a single
# global catalog (see app/db/models.py's multi-tenant block); only the
# *assignment* of these roles to a member is org-scoped, via
# OrganizationMembership -> membership_roles. Created lazily on first use
# (org creation / invite), not at app startup -- an environment that never
# creates an org never gets these rows either.
ORG_ADMIN_ROLE = "org_admin"
ORG_ADMIN_PERMISSIONS = [
    "manage_org", "manage_teams", "manage_api_keys", "manage_oauth_clients", "manage_sso",
    # Org admins previously had no visibility into their own org's
    # workflow-bundles catalog at all -- workflow.read/manage lived only
    # on scientist/viewer (added for the omnibioai-workflow-bundles IAM
    # integration, see permission_names.py), so an org_admin needed a
    # second role grant just to see it. workflow.read/manage fit
    # org_admin's existing "administer this org's resources" character
    # (same shape as manage_teams/manage_api_keys/manage_sso above);
    # workflow.execute/workflow.publish deliberately stay scientist-only
    # -- running/publishing a workflow is a distinct operator capability,
    # not an org-administration one.
    "workflow.read", "workflow.manage",
    # Same reasoning as workflow.read/manage above, for TES's own
    # execution-run history (a distinct resource from the workflow-bundles
    # catalog, see permission_names.py's runs.read) -- org_admin can see
    # its org's runs without also being able to submit/cancel them
    # (workflow.execute, deliberately not added here for the same reason
    # workflow.execute itself isn't: that's an operator capability, not
    # an org-administration one).
    "runs.read",
]
ORG_MEMBER_ROLE = "org_member"

# PR13: default assignable roles matching the scenario matrix in this PR's
# report -- Scientist can execute workflows/read datasets/use models but
# not publish; Viewer can read but not execute/manage anything. Both
# platform-wide (organization_id=None), same as org_admin/org_member
# above -- any org can assign either to its own members, but only a
# Platform Admin can edit/delete the role definitions themselves.
SCIENTIST_ROLE = "scientist"
SCIENTIST_PERMISSIONS = ["workflow.execute", "dataset.read", "model.use"]
VIEWER_ROLE = "viewer"
VIEWER_PERMISSIONS = ["dataset.read", "workflow.read"]


def create_organization(db: Session, name: str, slug: str, creator: User) -> Organization:
    org = Organization(
        slug=slug,
        name=name,
        created_by_user_id=creator.id,
        created_at=datetime.utcnow(),
    )
    db.add(org)
    db.flush()

    admin_role = role_service.get_or_create_role(db, ORG_ADMIN_ROLE, ORG_ADMIN_PERMISSIONS)
    membership = OrganizationMembership(
        organization_id=org.id,
        user_id=creator.id,
        status="active",
        joined_at=datetime.utcnow(),
        roles=[admin_role],
    )
    db.add(membership)
    db.commit()
    db.refresh(org)
    return org


def get_organization(db: Session, org_id: int) -> Organization | None:
    return db.query(Organization).filter(Organization.id == org_id).first()


def get_organization_by_slug(db: Session, slug: str) -> Organization | None:
    return db.query(Organization).filter(Organization.slug == slug).first()


def list_organizations_for_user(db: Session, user_id: int) -> list[Organization]:
    return (
        db.query(Organization)
        .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
        )
        .all()
    )


def ensure_org_admin_permissions(db: Session) -> None:
    """Idempotent startup top-up, mirrors init_admin.py's create_admin()
    pattern for the global "admin" role. get_or_create_role only sets a
    role's permissions at the moment it's first created -- an org_admin
    Role row created by an earlier deploy does not retroactively gain a
    permission later added to ORG_ADMIN_PERMISSIONS (Phase 2 PR1 added
    "manage_oauth_clients") unless something tops it up on every startup.
    Only ever adds, never removes, so an operator who deliberately edited
    org_admin's permissions via the role CRUD endpoints keeps anything else
    they added or removed beyond this list.
    """
    role = role_service.get_role_by_name(db, ORG_ADMIN_ROLE)
    if not role:
        return  # no org has been created yet -- nothing to top up
    existing = {p.name for p in role.permissions}
    if set(ORG_ADMIN_PERMISSIONS) <= existing:
        return
    role_service.update_role_permissions(db, role, sorted(existing | set(ORG_ADMIN_PERMISSIONS)))


def ensure_default_org_roles(db: Session) -> None:
    """PR13: eagerly seeds scientist/viewer at every startup -- create if
    missing, else top up any permission missing from the current set
    (never remove, so an operator who deliberately edited either role via
    the role CRUD endpoints keeps anything else they changed). Unlike
    org_admin/org_member above, there is no natural request-time call site
    that would create these lazily (org_admin is created on first
    create_organization, org_member on first invite/JIT-provision) -- an
    org admin needs to see scientist/viewer in the catalog to assign them
    before any such trigger would fire, so this runs unconditionally at
    startup instead, mirroring init_admin.py's ensure_platform_admin_role
    pattern (create-or-top-up) rather than ensure_org_admin_permissions'
    (top-up only, does nothing if the role doesn't exist yet -- correct
    for org_admin, which assumes an org has already been created, but that
    assumption doesn't hold for scientist/viewer).
    """
    for name, perms in ((SCIENTIST_ROLE, SCIENTIST_PERMISSIONS), (VIEWER_ROLE, VIEWER_PERMISSIONS)):
        role = role_service.get_role_by_name(db, name)
        if not role:
            role_service.create_role(db, name, perms, description=f"Default {name} role")
        else:
            existing = {p.name for p in role.permissions}
            if not set(perms) <= existing:
                role_service.update_role_permissions(db, role, sorted(existing | set(perms)))


ALLOWED_ORG_STATUSES = {"active", "suspended"}


def update_organization(
    db: Session,
    org: Organization,
    name: str | None,
    status: str | None = None,
    status_reason: str | None = None,
    actor_user_id: int | None = None,
) -> Organization:
    """`status`/`status_reason`/`actor_user_id` are Phase 3 PR2 additions
    -- the caller (routes_orgs.py) is responsible for confirming the
    actor actually holds `manage_all_orgs` before ever passing a non-None
    `status` here; this function only validates the *value*, not who's
    allowed to set it, matching this codebase's existing separation
    (authorization in the route/dependency layer, validation in the
    service layer).

    Raises ValueError for an unrecognized status -- mapped to 400 by the
    route, the same pattern org_sso_service.set_enforced's lockout guard
    already uses for its own ValueError.

    The status_changed_* columns are only touched when `status` actually
    changes value (a no-op PATCH -- e.g. re-sending the current status,
    or a name-only update -- must not churn the timestamp/actor/reason
    for a change that didn't happen). PR4's audit pipeline should hook in
    here once it exists -- this is the one call site a "status changed"
    event would be emitted from; deliberately not building any audit
    mechanism now (see ~/phase3_remediation_plan.md's PR4 scope).
    """
    if name is not None:
        org.name = name

    if status is not None and status != org.status:
        if status not in ALLOWED_ORG_STATUSES:
            raise ValueError(f"Unknown status: {status!r} (expected one of {sorted(ALLOWED_ORG_STATUSES)})")
        org.status = status
        org.status_changed_at = datetime.utcnow()
        org.status_changed_reason = status_reason
        org.status_changed_by_user_id = actor_user_id

    db.commit()
    db.refresh(org)
    return org


def list_members(db: Session, org_id: int) -> list[OrganizationMembership]:
    return (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org_id)
        .all()
    )


def get_membership(db: Session, org_id: int, user_id: int) -> OrganizationMembership | None:
    return (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == user_id,
        )
        .first()
    )


def jit_provision_membership(db: Session, organization_id: int, user_id: int) -> OrganizationMembership:
    """Phase 2 PR4: ensures a successful enterprise SSO login results in
    real org membership, not just a User row -- otherwise org_id/org_role
    resolution (resolve_primary_membership, used by generate_tokens) would
    never reflect the org whose IdP actually authenticated the user.
    Default role is org_member (no permissions) -- basic JIT provisioning
    only, deliberately not group sync or automatic role mapping (both out
    of scope for this PR).

    Idempotent: a user who already has a membership in this org (e.g. a
    repeat SSO login, or they were already a member some other way) is
    left completely untouched -- never duplicated, and any custom roles
    they already hold here are never overwritten back down to org_member.
    """
    existing = get_membership(db, organization_id, user_id)
    if existing:
        return existing

    member_role = role_service.get_or_create_role(db, ORG_MEMBER_ROLE, [])
    membership = OrganizationMembership(
        organization_id=organization_id,
        user_id=user_id,
        status="active",
        joined_at=datetime.utcnow(),
        roles=[member_role],
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)
    audit_service.log_event(
        db, AuditEventType.ORG_MEMBERSHIP_CHANGED, actor_user_id=user_id, target_user_id=user_id,
        organization_id=organization_id, resource_type="organization_membership", resource_id=membership.id,
        after_state={"status": membership.status, "roles": [member_role.name]},
        metadata={"reason": "sso_jit_provisioning"},
    )
    return membership


def invite_member(
    db: Session, org: Organization, email: str, invited_by: User
) -> OrganizationMembership | None:
    """Returns None if no account exists for that email yet -- inviting an
    unregistered address isn't supported in this change (caller translates
    to a 404); the person has to register/log in at least once first."""
    invitee = db.query(User).filter(User.email == email).first()
    if not invitee:
        return None

    existing = get_membership(db, org.id, invitee.id)
    if existing:
        return existing

    member_role = role_service.get_or_create_role(db, ORG_MEMBER_ROLE, [])
    membership = OrganizationMembership(
        organization_id=org.id,
        user_id=invitee.id,
        status="invited",
        invited_by_user_id=invited_by.id,
        joined_at=datetime.utcnow(),
        roles=[member_role],
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)
    audit_service.log_event(
        db, AuditEventType.ORG_MEMBERSHIP_CHANGED, actor_user_id=invited_by.id, target_user_id=invitee.id,
        organization_id=org.id, resource_type="organization_membership", resource_id=membership.id,
        after_state={"status": membership.status, "roles": [member_role.name]},
        metadata={"reason": "invited", "email": email},
    )
    return membership


def set_member_roles(
    db: Session, membership: OrganizationMembership, roles: list, actor_user_id: int | None = None,
) -> OrganizationMembership:
    """`roles` must already be resolved Role objects (see
    role_service.resolve_roles) -- mirrors role_service.set_user_roles'
    contract for the same reason: validation happens once, at the call site,
    before this is invoked."""
    before = sorted(r.name for r in membership.roles)
    membership.roles = roles
    db.commit()
    db.refresh(membership)

    after = sorted(r.name for r in membership.roles)
    # PR9: one event per call, even though a full replace can add and
    # remove roles simultaneously -- see role_service.update_role_
    # permissions' identical reasoning. No-op resubmissions emit nothing.
    if before != after:
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id, target_user_id=membership.user_id,
            organization_id=membership.organization_id, resource_type="organization_membership_roles",
            resource_id=membership.id, before_state={"roles": before}, after_state={"roles": after},
        )
    return membership


def permissions_for_membership(membership: OrganizationMembership) -> set[str]:
    return role_service.permissions_for_roles(membership.roles)


# ---------------------------------------------------------------------------
# Phase 3 PR3B: single-role add/remove for one org membership, mirroring
# role_service.add_user_role/remove_user_role exactly (same "only touch
# the one role passed in" contract) but for the org-scoped membership_roles
# assignment rather than a user's global roles. Kept alongside, not instead
# of, set_member_roles above -- that full-replace PUT endpoint is unchanged.
# ---------------------------------------------------------------------------


def add_member_role(
    db: Session, membership: OrganizationMembership, role, actor_user_id: int | None = None,
) -> OrganizationMembership:
    if role not in membership.roles:
        membership.roles.append(role)
        db.commit()
        db.refresh(membership)
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id, target_user_id=membership.user_id,
            organization_id=membership.organization_id, resource_type="organization_membership_roles",
            resource_id=membership.id, after_state={"role": role.name},
        )
    return membership


def remove_member_role(
    db: Session, membership: OrganizationMembership, role, actor_user_id: int | None = None,
) -> OrganizationMembership:
    if role in membership.roles:
        membership.roles.remove(role)
        db.commit()
        db.refresh(membership)
        audit_service.log_event(
            db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id, target_user_id=membership.user_id,
            organization_id=membership.organization_id, resource_type="organization_membership_roles",
            resource_id=membership.id, before_state={"role": role.name},
        )
    return membership


def resolve_primary_membership(db: Session, user_id: int) -> OrganizationMembership | None:
    """Picks the one org membership a fresh JWT's org_id/org_role claims
    should reflect (Phase 1 PR3). A user can belong to multiple orgs, but a
    token only carries one org context at a time -- prefers the Default
    Organization (where every backfilled pre-PR3 user ends up) so existing
    accounts get a stable, predictable org_id the moment they next log in,
    falling back to the earliest membership for users who only belong to
    org(s) they created themselves. Returns None for a user with no active
    membership anywhere yet (pre-backfill, or a brand new account) -- a
    token with org_id=None is a valid, well-defined state, not an error.
    """
    memberships = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
        )
        .order_by(OrganizationMembership.id)
        .all()
    )
    if not memberships:
        return None
    for m in memberships:
        if m.organization.slug == "default":
            return m
    return memberships[0]
