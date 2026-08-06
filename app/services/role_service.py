import difflib

from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY, PermissionScope, is_known_permission
from app.db.models import Permission, Role, User, membership_roles, user_roles
from app.services import audit_service
from app.services.audit_service import AuditEventType


def list_roles(db: Session) -> list[Role]:
    return db.query(Role).all()


def list_roles_for_scope(db: Session, organization_id: int) -> list[Role]:
    """PR13: every role visible to `organization_id` -- every platform-wide
    role (organization_id IS NULL) plus this org's own custom roles. This is
    the function `GET /orgs/{org_id}/roles` and `GET
    /organizations/{organization_id}/roles` must use instead of list_roles()
    now that Role.organization_id carries real data -- list_roles() returns
    literally every role in the system, including every *other* org's
    private custom roles, which would otherwise leak across tenants."""
    return (
        db.query(Role)
        .filter((Role.organization_id.is_(None)) | (Role.organization_id == organization_id))
        .all()
    )


def get_role(db: Session, role_id: int) -> Role | None:
    return db.query(Role).filter(Role.id == role_id).first()


def get_role_by_name(db: Session, name: str, organization_id: int | None = None) -> Role | None:
    """Exact-scope lookup: `organization_id=None` (the default, matching
    every pre-PR13 call site unchanged) looks up a platform-wide role only.
    Passing a real organization_id looks up a custom role owned by exactly
    that org -- it does NOT also match a platform-wide role of the same
    name (use get_role_in_scope for "is this name visible/assignable to
    this org at all")."""
    return (
        db.query(Role)
        .filter(Role.name == name, Role.organization_id == organization_id)
        .first()
    )


def get_role_in_scope(db: Session, name: str, organization_id: int) -> Role | None:
    """PR13: resolves a role name the way an org member would see it --
    either a platform-wide role, or this org's own custom role of that
    name. Used to resolve org-scoped role *assignments*
    (resolve_roles_for_org), where either kind is a legal target."""
    return (
        db.query(Role)
        .filter(Role.name == name, (Role.organization_id.is_(None)) | (Role.organization_id == organization_id))
        .first()
    )


def get_user(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id).first()


def role_in_use(db: Session, role_id: int) -> bool:
    """PR13 fix: previously checked only user_roles (global assignment),
    silently missing membership_roles (org-scoped assignment) entirely --
    e.g. deleting "org_admin" while it's assigned to a membership would not
    have been caught here. Low-consequence before PR13 (nothing deleted
    in-use org-scoped roles), but now load-bearing: scientist/viewer and any
    custom org role are deletable via the new catalog-CRUD endpoints, and an
    in-use role must be blocked (409), not left to hit a raw FK error or
    silently orphan membership_roles rows."""
    in_global_use = db.query(user_roles).filter(user_roles.c.role_id == role_id).first() is not None
    in_org_use = db.query(membership_roles).filter(membership_roles.c.role_id == role_id).first() is not None
    return in_global_use or in_org_use


def get_or_create_role(db: Session, name: str, permission_names: list[str] | None = None) -> Role:
    """Idempotent role lookup/creation. Does not commit -- callers own the
    transaction (mirrors init_admin.py's bootstrap pattern, generalized so
    both startup bootstrap and per-request signup paths can share it).
    Always platform-wide (organization_id=None) -- every call site is a
    platform-wide bootstrap role (user/org_admin/org_member/scientist/
    viewer), never a per-org custom role."""
    role = get_role_by_name(db, name)
    if not role:
        role = Role(name=name, permissions=_get_or_create_permissions(db, permission_names or []))
        db.add(role)
        db.flush()
    return role


def assign_default_role(db: Session, user: User) -> None:
    """Grants the baseline "user" role to a newly created account. Does not
    commit -- callers own the transaction, call this before their own
    db.commit()."""
    role = get_or_create_role(db, "user")
    if role not in user.roles:
        user.roles.append(role)


def _check_name_available(db: Session, name: str, organization_id: int | None, exclude_role_id: int | None = None) -> None:
    """PR13: app-level uniqueness-within-scope, since the DB no longer
    enforces it (see 0016_role_org_scope's migration docstring for why a
    DB-level composite constraint can't express this correctly under
    MySQL's NULL semantics). A platform-wide name (organization_id=None) is
    reserved everywhere -- no org may create a custom role that shadows it.
    An org-custom name only has to be unique within its own org; two
    different orgs may each have their own role called e.g. "QA Reviewer"."""
    platform_clash = get_role_by_name(db, name, organization_id=None)
    if platform_clash and platform_clash.id != exclude_role_id:
        raise ValueError(f"Role name {name!r} is already taken by a platform-wide role")
    if organization_id is not None:
        org_clash = get_role_by_name(db, name, organization_id=organization_id)
        if org_clash and org_clash.id != exclude_role_id:
            raise ValueError(f"Role name {name!r} is already taken by another role in this organization")


def create_role(
    db: Session, name: str, permission_names: list[str], description: str | None = None,
    actor_user_id: int | None = None, organization_id: int | None = None,
) -> Role:
    _check_name_available(db, name, organization_id)
    if organization_id is not None:
        _validate_org_scoped_permission_names(db, permission_names, organization_id, actor_user_id, role_name=name)
    else:
        _validate_permission_names(permission_names)
    role = Role(
        name=name, permissions=_get_or_create_permissions(db, permission_names),
        description=description, organization_id=organization_id,
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    audit_service.log_event(
        db, AuditEventType.ROLE_CREATED, actor_user_id=actor_user_id,
        organization_id=organization_id,
        resource_type="role", resource_id=role.id,
        after_state={"name": role.name, "description": role.description, "permissions": sorted(permission_names)},
    )
    return role


def update_role_permissions(
    db: Session, role: Role, permission_names: list[str], description: str | None = None,
    actor_user_id: int | None = None,
) -> Role:
    """`description` follows the same "None means leave unchanged" contract
    as OrganizationUpdate.name/status elsewhere in this codebase -- a
    caller updating only permissions (every existing test/caller) must not
    silently blank out a description someone already set."""
    if role.organization_id is not None:
        _validate_org_scoped_permission_names(
            db, permission_names, role.organization_id, actor_user_id, role_name=role.name, role_id=role.id,
        )
    else:
        _validate_permission_names(permission_names)
    before = sorted(p.name for p in role.permissions)
    role.permissions = _get_or_create_permissions(db, permission_names)
    if description is not None:
        role.description = description
    db.commit()
    db.refresh(role)

    after = sorted(permission_names)
    added, removed = set(after) - set(before), set(before) - set(after)
    # PR9: exactly one audit event per call -- a mixed add+remove replace
    # is still one row (PERMISSION_GRANTED, since a net new capability was
    # introduced), with the full before/after + added/removed diff in the
    # payload rather than splitting into two rows for one mutation. A true
    # no-op (resubmitting the identical permission set) emits nothing.
    if added or removed:
        event_type = AuditEventType.PERMISSION_GRANTED if added else AuditEventType.PERMISSION_REVOKED
        audit_service.log_event(
            db, event_type, actor_user_id=actor_user_id,
            organization_id=role.organization_id,
            resource_type="role", resource_id=role.id,
            before_state={"permissions": before}, after_state={"permissions": after},
            metadata={"added": sorted(added), "removed": sorted(removed)},
        )
    return role


# ---------------------------------------------------------------------------
# Phase 3 PR3B: single-role add/remove, reused by both the platform-admin
# (/platform/users/{id}/roles) and org-scoped (/orgs/{id}/members/{id}/roles)
# route surfaces. Deliberately separate from set_user_roles above (a
# full-replace operation, kept for the legacy /users/{id}/roles PUT
# endpoint) -- these two only ever touch the one role passed in, leaving
# every other role a user already holds untouched.
# ---------------------------------------------------------------------------


def add_user_role(db: Session, user: User, role: Role, actor_user_id: int | None = None) -> User:
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        db.refresh(user)
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id, target_user_id=user.id,
            resource_type="role", resource_id=role.id, after_state={"role": role.name},
        )
    return user


def remove_user_role(db: Session, user: User, role: Role, actor_user_id: int | None = None) -> User:
    if role in user.roles:
        user.roles.remove(role)
        db.commit()
        db.refresh(user)
        audit_service.log_event(
            db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id, target_user_id=user.id,
            resource_type="role", resource_id=role.id, before_state={"role": role.name},
        )
    return user


def delete_role(db: Session, role: Role) -> None:
    db.delete(role)
    db.commit()


def resolve_roles(db: Session, role_names: list[str]) -> list[Role]:
    """Resolve role names to existing platform-wide Role rows, for a global
    (user_roles) assignment. Unlike permissions, roles must already exist
    (they are managed exclusively via the role CRUD endpoints).

    PR13: rejects a name that only resolves to an org-scoped custom role
    (organization_id is not None) -- an org-private custom role must never
    be assignable as a *global* role to a user account; it only makes sense
    scoped to the org that owns it (see resolve_roles_for_org)."""
    roles = []
    for name in role_names:
        role = get_role_by_name(db, name)
        if not role:
            raise ValueError(f"Unknown role: {name}")
        roles.append(role)
    return roles


GLOBAL_SCOPE_PERMISSIONS = frozenset(
    p.name for p in REGISTRY.values() if p.scope == PermissionScope.GLOBAL
)


def resolve_roles_for_org(
    db: Session,
    role_names: list[str],
    organization_id: int,
    caller_is_platform_admin: bool,
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
) -> list[Role]:
    """PR13: org-scoped counterpart to resolve_roles, used by every
    org-scoped role-*assignment* endpoint (routes_organization_roles.py,
    routes_orgs.py). Resolves each name against this org's visible catalog
    (platform-wide + this org's own custom roles, via get_role_in_scope).

    Security-critical (see this PR's report, "Finding 2"): before PR13, an
    Org Admin (manage_org, scoped to their own org) could already assign
    any existing role by name -- including the literal "admin" or
    "platform_admin" -- to any other member of their org via this same
    endpoint family, with no restriction beyond a self-escalation guard
    that only fires when the target is the caller themself. That was
    low-consequence only because org-scoped (membership_roles) permissions
    never reached a user's JWT `permissions` claim. PR13's JWT cutover
    (auth_service.build_user_claims) makes them reach it -- so, unless the
    caller is a Platform Admin, this now refuses to resolve any role whose
    permission set contains a GLOBAL-scope permission, closing the path
    before it becomes a live, system-wide privilege escalation. Every
    refusal is audit-logged (ROLE_ASSIGNMENT_DENIED) before raising -- a
    repeated attempt is itself a signal worth being able to see later, not
    just a 400/403 with no server-side trail.
    """
    roles = []
    for name in role_names:
        role = get_role_in_scope(db, name, organization_id)
        if not role:
            raise ValueError(f"Unknown role: {name}")
        if not caller_is_platform_admin:
            offending = GLOBAL_SCOPE_PERMISSIONS & {p.name for p in role.permissions}
            if offending:
                audit_service.log_event(
                    db, AuditEventType.ROLE_ASSIGNMENT_DENIED, actor_user_id=actor_user_id,
                    target_user_id=target_user_id, organization_id=organization_id,
                    resource_type="role", resource_id=role.id,
                    metadata={
                        "reason": "org_scoped_assignment_of_global_permission_role",
                        "role": name, "offending_permissions": sorted(offending),
                    },
                )
                raise ValueError(
                    f"Role {name!r} grants platform-wide permissions "
                    f"({', '.join(sorted(offending))}) and can only be assigned by a Platform Admin"
                )
        roles.append(role)
    return roles


def set_user_roles(db: Session, user: User, roles: list[Role]) -> User:
    user.roles = roles
    db.commit()
    db.refresh(user)
    return user


def permissions_for_roles(roles: list[Role]) -> set[str]:
    perms = set()
    for role in roles:
        perms.update(p.name for p in role.permissions)
    return perms


def _validate_permission_names(names: list[str]) -> None:
    """PR4: gate the one fully-open permission-creation path (create_role/
    update_role_permissions, reachable from POST/PUT /roles) against the
    Permission Registry (app/core/permission_names.py). A name already
    known to the registry -- legacy or newly reserved -- is unaffected;
    only a genuinely unregistered string is rejected, so every existing
    role/test continues to work unchanged.

    PR6: the rejection message is enriched with nearest-name suggestions
    (stdlib difflib.get_close_matches, no third-party dependency) when any
    exist, purely informational -- the validation outcome (reject unknown
    names) is unchanged from PR4, only the message text gains a "Did you
    mean" hint."""
    for name in names:
        if not is_known_permission(name):
            suggestions = difflib.get_close_matches(name, REGISTRY.keys(), n=3, cutoff=0.6)
            if suggestions:
                raise ValueError(
                    f"Unknown permission: {name}. Did you mean: {', '.join(suggestions)}?"
                )
            raise ValueError(f"Unknown permission: {name}")


def _validate_org_scoped_permission_names(
    db: Session, names: list[str], organization_id: int,
    actor_user_id: int | None, role_name: str, role_id: int | None = None,
) -> None:
    """PR13 (Finding 2, layer 1): a custom org role can never be created or
    edited to hold a GLOBAL-scope registry permission (e.g. manage_all_orgs,
    manage_roles, platform.manage_infra) -- those are structurally
    platform-only capabilities. Runs the normal registry check first (an
    org role still can't invent an unregistered permission name), then the
    GLOBAL-scope check. On rejection, audit-logs ROLE_ASSIGNMENT_DENIED
    before raising, mirroring resolve_roles_for_org's layer-2 guard -- both
    denial paths get a trail, not just a 400 with nothing recorded."""
    _validate_permission_names(names)
    offending = GLOBAL_SCOPE_PERMISSIONS & set(names)
    if offending:
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNMENT_DENIED, actor_user_id=actor_user_id,
            organization_id=organization_id,
            resource_type="role", resource_id=role_id,
            metadata={
                "reason": "org_scoped_role_with_global_permission",
                "role": role_name, "offending_permissions": sorted(offending),
            },
        )
        raise ValueError(
            f"Organization-scoped roles cannot hold platform-wide permissions: {', '.join(sorted(offending))}"
        )


def assert_no_unregistered_permissions(db: Session) -> None:
    """PR6: startup drift check. Every `Permission` row in the database
    must exist in the Permission Registry -- the registry is the permanent
    vocabulary layer, and the database must never be allowed to invent a
    permission outside it. Called once from app/main.py's bootstrap
    sequence; never per-request, never as a background task. Raises
    RuntimeError (not ValueError -- this is a deployment/data-integrity
    failure, not a request-validation failure) so startup fails loudly
    rather than serving traffic against a drifted database."""
    unknown = sorted(p.name for p in db.query(Permission).all() if not is_known_permission(p.name))
    if unknown:
        raise RuntimeError(
            "Permission Registry drift detected: the following Permission "
            f"rows exist in the database but are not in the registry: {unknown}"
        )


def _get_or_create_permissions(db: Session, names: list[str]) -> list[Permission]:
    perms = []
    for name in names:
        perm = db.query(Permission).filter(Permission.name == name).first()
        if not perm:
            perm = Permission(name=name)
            db.add(perm)
            db.flush()
        perms.append(perm)
    return perms
