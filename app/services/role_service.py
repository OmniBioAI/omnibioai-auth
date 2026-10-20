"""
OmniBioAI app.services.role_service.

Purpose:
    Defines list_roles, list_roles_for_scope, get_role and get_role_by_name for app.services.role_service.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import difflib

from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY, PermissionScope, is_known_permission
from app.db.models import Permission, Role, User, membership_roles, user_roles
from app.services import audit_service
from app.services.audit_service import AuditEventType

PLATFORM_OWNER_ROLE = "platform_admin"
ADMIN_ROLE = "admin"
PRIVILEGED_SINGLETON_ROLES = frozenset({PLATFORM_OWNER_ROLE, ADMIN_ROLE})
DESIGNATED_ADMIN_USER_ID = 1


class PrivilegedRolePolicyError(ValueError):
    pass


def _lock_privileged_role_rows(db: Session) -> dict[str, Role]:
    """Serialize privileged assignment decisions on stable role rows.

    InnoDB honors FOR UPDATE; SQLite test databases safely degrade to
    sequential semantics.  Lock ordering is fixed to avoid deadlocks when a
    transition touches both singleton roles.
    """
    rows = (
        db.query(Role)
        .filter(Role.organization_id.is_(None), Role.name.in_(sorted(PRIVILEGED_SINGLETON_ROLES)))
        .order_by(Role.name)
        .with_for_update()
        .all()
    )
    return {role.name: role for role in rows}


def _active_holders(db: Session, role_name: str, exclude_user_id: int | None = None) -> list[User]:
    query = (
        db.query(User)
        .join(user_roles, user_roles.c.user_id == User.id)
        .join(Role, Role.id == user_roles.c.role_id)
        .filter(User.status == "active", Role.name == role_name, Role.organization_id.is_(None))
    )
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    return query.order_by(User.id).all()


def _audit_privileged_denial(
    db: Session, *, actor_user_id: int | None, target_user_id: int,
    role_name: str, reason: str,
) -> None:
    audit_service.log_event(
        db, AuditEventType.ROLE_ASSIGNMENT_DENIED,
        actor_user_id=actor_user_id, target_user_id=target_user_id,
        resource_type="role", metadata={"role": role_name, "reason": reason},
    )


def validate_privileged_role_transition(
    db: Session,
    user: User,
    new_roles: list[Role],
    *,
    actor_user_id: int | None = None,
    enforce_nonempty: bool = True,
    target_active: bool | None = None,
) -> None:
    """Enforce the designated Owner/Admin policy for one user transition.

    User 1 is the stable designated non-owner Admin. The sole Platform
    Owner may also hold Admin; no other identity may hold either privileged
    assignment. Role rows serialize concurrent decisions in the DB.
    """
    _lock_privileged_role_rows(db)
    current = {role.name for role in user.roles}
    requested = {role.name for role in new_roles}
    privileged = requested & PRIVILEGED_SINGLETON_ROLES
    is_active = user.status == "active" if target_active is None else target_active

    if user.id == DESIGNATED_ADMIN_USER_ID and PLATFORM_OWNER_ROLE in requested:
        _audit_privileged_denial(
            db, actor_user_id=actor_user_id, target_user_id=user.id,
            role_name=PLATFORM_OWNER_ROLE, reason="designated_admin_cannot_become_platform_owner",
        )
        raise PrivilegedRolePolicyError("The designated Admin identity cannot become Platform Owner")

    # The Platform Owner's required composition is platform_admin + admin.
    # User 1 remains the separate designated Admin and may not lose Admin
    # through ordinary role APIs.
    if PLATFORM_OWNER_ROLE in current and ADMIN_ROLE not in requested:
        _audit_privileged_denial(
            db, actor_user_id=actor_user_id, target_user_id=user.id,
            role_name=ADMIN_ROLE, reason="platform_owner_admin_role_is_required",
        )
        raise PrivilegedRolePolicyError("Platform Owner must retain the Admin role")
    if user.id == DESIGNATED_ADMIN_USER_ID and ADMIN_ROLE in current and ADMIN_ROLE not in requested:
        _audit_privileged_denial(
            db, actor_user_id=actor_user_id, target_user_id=user.id,
            role_name=ADMIN_ROLE, reason="designated_admin_role_is_required",
        )
        raise PrivilegedRolePolicyError("The designated Admin identity must retain the Admin role")

    if PLATFORM_OWNER_ROLE in requested and ADMIN_ROLE not in requested:
        _audit_privileged_denial(
            db, actor_user_id=actor_user_id, target_user_id=user.id,
            role_name=PLATFORM_OWNER_ROLE, reason="platform_owner_requires_admin_role",
        )
        raise PrivilegedRolePolicyError("Platform Owner must hold both platform_admin and admin")

    if ADMIN_ROLE in requested and user.id != DESIGNATED_ADMIN_USER_ID and PLATFORM_OWNER_ROLE not in requested:
        _audit_privileged_denial(
            db, actor_user_id=actor_user_id, target_user_id=user.id,
            role_name=ADMIN_ROLE, reason="admin_assignment_not_designated_identity",
        )
        raise PrivilegedRolePolicyError("Global Admin is limited to user 1 and the Platform Owner")

    if is_active:
        if PLATFORM_OWNER_ROLE in privileged:
            holders = _active_holders(db, PLATFORM_OWNER_ROLE, exclude_user_id=user.id)
            if holders:
                _audit_privileged_denial(
                    db, actor_user_id=actor_user_id, target_user_id=user.id,
                    role_name=PLATFORM_OWNER_ROLE, reason="active_singleton_already_assigned",
                )
                raise PrivilegedRolePolicyError("An active Platform Owner is already assigned")

        if ADMIN_ROLE in privileged:
            holders = _active_holders(db, ADMIN_ROLE, exclude_user_id=user.id)
            disallowed = [
                holder for holder in holders
                if holder.id != DESIGNATED_ADMIN_USER_ID
                and PLATFORM_OWNER_ROLE not in {role.name for role in holder.roles}
            ]
            owner_count = sum(
                1 for holder in holders
                if PLATFORM_OWNER_ROLE in {role.name for role in holder.roles}
            )
            designated_count = sum(1 for holder in holders if holder.id == DESIGNATED_ADMIN_USER_ID)
            if disallowed or owner_count > 1 or designated_count > 1 or len(holders) >= 2:
                _audit_privileged_denial(
                    db, actor_user_id=actor_user_id, target_user_id=user.id,
                    role_name=ADMIN_ROLE, reason="admin_identity_limit_exceeded",
                )
                raise PrivilegedRolePolicyError(
                    "Global Admin is limited to the designated Admin and the sole Platform Owner"
                )

        if enforce_nonempty:
            removed = (current & PRIVILEGED_SINGLETON_ROLES) - privileged
            for role_name in sorted(removed):
                # The paired Owner/Admin transition is only available via
                # replace_privileged_role, never through ordinary role APIs.
                if role_name == PLATFORM_OWNER_ROLE:
                    _audit_privileged_denial(
                        db, actor_user_id=actor_user_id, target_user_id=user.id,
                        role_name=role_name, reason="use_privileged_replacement_workflow",
                    )
                    raise PrivilegedRolePolicyError(
                        "Use the explicit privileged replacement workflow to replace Platform Owner"
                    )
                if not _active_holders(db, role_name, exclude_user_id=user.id):
                    _audit_privileged_denial(
                        db, actor_user_id=actor_user_id, target_user_id=user.id,
                        role_name=role_name, reason="cannot_remove_last_active_holder",
                    )
                    raise PrivilegedRolePolicyError(
                        f"Cannot remove the last active holder of {role_name!r}; use privileged replacement"
                    )


def validate_user_activation(db: Session, user: User, actor_user_id: int | None = None) -> None:
    validate_privileged_role_transition(
        db, user, list(user.roles), actor_user_id=actor_user_id, enforce_nonempty=False,
        target_active=True,
    )


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
    db.flush()
    db.refresh(role)
    audit_service.log_event(
        db, AuditEventType.ROLE_CREATED, actor_user_id=actor_user_id,
        organization_id=organization_id,
        resource_type="role", resource_id=role.id,
        after_state={"name": role.name, "description": role.description, "permissions": sorted(permission_names)},
        commit=False,
    )
    db.commit()
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
            commit=False,
        )
    db.commit()
    db.refresh(role)
    return role


# ---------------------------------------------------------------------------
# Phase 3 PR3B: single-role add/remove, reused by both the platform-admin
# (/platform/users/{id}/roles) and org-scoped (/orgs/{id}/members/{id}/roles)
# route surfaces. Deliberately separate from set_user_roles above (a
# full-replace operation, kept for the legacy /users/{id}/roles PUT
# endpoint) -- these two only ever touch the one role passed in, leaving
# every other role a user already holds untouched.
# ---------------------------------------------------------------------------


def add_user_role(
    db: Session, user: User, role: Role, actor_user_id: int | None = None,
    *, commit: bool = True,
) -> User:
    if role not in user.roles:
        validate_privileged_role_transition(
            db, user, [*user.roles, role], actor_user_id=actor_user_id
        )
        user.roles.append(role)
        db.flush()
        db.refresh(user)
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id, target_user_id=user.id,
            resource_type="role", resource_id=role.id, after_state={"role": role.name},
            commit=False,
        )
        if commit:
            db.commit()
    return user


def remove_user_role(db: Session, user: User, role: Role, actor_user_id: int | None = None) -> User:
    if role in user.roles:
        validate_privileged_role_transition(
            db, user, [r for r in user.roles if r.id != role.id], actor_user_id=actor_user_id
        )
        user.roles.remove(role)
        db.flush()
        db.refresh(user)
        audit_service.log_event(
            db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id, target_user_id=user.id,
            resource_type="role", resource_id=role.id, before_state={"role": role.name},
            commit=False,
        )
        db.commit()
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


def set_user_roles(
    db: Session, user: User, roles: list[Role], actor_user_id: int | None = None
) -> User:
    validate_privileged_role_transition(db, user, roles, actor_user_id=actor_user_id)
    before = {role.name: role for role in user.roles}
    after = {role.name: role for role in roles}
    user.roles = roles
    db.flush()
    for name in sorted(after.keys() - before.keys()):
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id,
            target_user_id=user.id, resource_type="role", resource_id=after[name].id,
            after_state={"role": name}, commit=False,
        )
    for name in sorted(before.keys() - after.keys()):
        audit_service.log_event(
            db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id,
            target_user_id=user.id, resource_type="role", resource_id=before[name].id,
            before_state={"role": name}, commit=False,
        )
    db.commit()
    db.refresh(user)
    return user


def replace_privileged_role(
    db: Session,
    role_name: str,
    current_user_id: int,
    replacement_user_id: int,
    actor_user_id: int,
    reason: str,
) -> tuple[User, User]:
    if role_name not in PRIVILEGED_SINGLETON_ROLES:
        raise ValueError("Role is not governed by singleton replacement policy")
    if current_user_id == replacement_user_id:
        raise ValueError("Current and replacement users must be different")
    if role_name == ADMIN_ROLE:
        raise PrivilegedRolePolicyError(
            "The designated Admin identity is fixed at user ID 1; use a separately approved identity migration to change it"
        )
    if replacement_user_id == DESIGNATED_ADMIN_USER_ID:
        raise PrivilegedRolePolicyError("The designated Admin identity cannot become Platform Owner")

    try:
        roles = _lock_privileged_role_rows(db)
        role = roles.get(role_name)
        if role is None:
            raise LookupError("Role not found")
        users = (
            db.query(User)
            .filter(User.id.in_([current_user_id, replacement_user_id]))
            .order_by(User.id)
            .with_for_update()
            .all()
        )
        by_id = {u.id: u for u in users}
        current = by_id.get(current_user_id)
        replacement = by_id.get(replacement_user_id)
        if current is None or replacement is None:
            raise LookupError("User not found")
        if current.status != "active" or replacement.status != "active":
            raise PrivilegedRolePolicyError("Both privileged identities must be active")
        holders = _active_holders(db, role_name)
        if [u.id for u in holders] != [current_user_id]:
            raise PrivilegedRolePolicyError(
                "Privileged replacement requires exactly the declared current active holder"
            )
        if role_name == PLATFORM_OWNER_ROLE:
            admin_role = get_role_by_name(db, ADMIN_ROLE)
            if admin_role is None or admin_role not in current.roles:
                raise PrivilegedRolePolicyError("Current Platform Owner must hold Admin before replacement")
            if admin_role in replacement.roles:
                raise PrivilegedRolePolicyError("Replacement Admin role would exceed the designated two identities")
            active_admins = _active_holders(db, ADMIN_ROLE)
            if {u.id for u in active_admins} != {current_user_id, DESIGNATED_ADMIN_USER_ID}:
                raise PrivilegedRolePolicyError(
                    "Owner replacement requires exactly the designated Admin and current Owner as active Admin holders"
                )

        current.roles.remove(role)
        replacement.roles.append(role)
        paired_admin_role = None
        if role_name == PLATFORM_OWNER_ROLE:
            current.roles.remove(admin_role)
            replacement.roles.append(admin_role)
            paired_admin_role = admin_role
        db.flush()
        audit_service.log_event(
            db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id,
            target_user_id=current.id, resource_type="role", resource_id=role.id,
            before_state={"role": role_name}, metadata={"reason": reason, "replacement_user_id": replacement.id},
            commit=False,
        )
        audit_service.log_event(
            db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id,
            target_user_id=replacement.id, resource_type="role", resource_id=role.id,
            after_state={"role": role_name}, metadata={"reason": reason, "replaced_user_id": current.id},
            commit=False,
        )
        if paired_admin_role is not None:
            audit_service.log_event(
                db, AuditEventType.ROLE_REMOVED, actor_user_id=actor_user_id,
                target_user_id=current.id, resource_type="role", resource_id=paired_admin_role.id,
                before_state={"role": ADMIN_ROLE},
                metadata={"reason": reason, "replacement_user_id": replacement.id}, commit=False,
            )
            audit_service.log_event(
                db, AuditEventType.ROLE_ASSIGNED, actor_user_id=actor_user_id,
                target_user_id=replacement.id, resource_type="role", resource_id=paired_admin_role.id,
                after_state={"role": ADMIN_ROLE},
                metadata={"reason": reason, "replaced_user_id": current.id}, commit=False,
            )
        audit_service.log_event(
            db, AuditEventType.PRIVILEGED_ROLE_REPLACED, actor_user_id=actor_user_id,
            target_user_id=replacement.id, resource_type="role", resource_id=role.id,
            before_state={"user_id": current.id}, after_state={"user_id": replacement.id},
            metadata={"role": role_name, "reason": reason}, commit=False,
        )
        db.commit()
        return current, replacement
    except Exception:
        db.rollback()
        raise


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
