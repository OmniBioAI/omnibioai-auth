import difflib

from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY, is_known_permission
from app.db.models import Permission, Role, User, user_roles


def list_roles(db: Session) -> list[Role]:
    return db.query(Role).all()


def get_role(db: Session, role_id: int) -> Role | None:
    return db.query(Role).filter(Role.id == role_id).first()


def get_role_by_name(db: Session, name: str) -> Role | None:
    return db.query(Role).filter(Role.name == name).first()


def get_user(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id).first()


def role_in_use(db: Session, role_id: int) -> bool:
    return db.query(user_roles).filter(user_roles.c.role_id == role_id).first() is not None


def get_or_create_role(db: Session, name: str, permission_names: list[str] | None = None) -> Role:
    """Idempotent role lookup/creation. Does not commit -- callers own the
    transaction (mirrors init_admin.py's bootstrap pattern, generalized so
    both startup bootstrap and per-request signup paths can share it)."""
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


def create_role(db: Session, name: str, permission_names: list[str], description: str | None = None) -> Role:
    _validate_permission_names(permission_names)
    role = Role(name=name, permissions=_get_or_create_permissions(db, permission_names), description=description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


def update_role_permissions(db: Session, role: Role, permission_names: list[str], description: str | None = None) -> Role:
    """`description` follows the same "None means leave unchanged" contract
    as OrganizationUpdate.name/status elsewhere in this codebase -- a
    caller updating only permissions (every existing test/caller) must not
    silently blank out a description someone already set."""
    _validate_permission_names(permission_names)
    role.permissions = _get_or_create_permissions(db, permission_names)
    if description is not None:
        role.description = description
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


def add_user_role(db: Session, user: User, role: Role) -> User:
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        db.refresh(user)
    return user


def remove_user_role(db: Session, user: User, role: Role) -> User:
    if role in user.roles:
        user.roles.remove(role)
        db.commit()
        db.refresh(user)
    return user


def delete_role(db: Session, role: Role) -> None:
    db.delete(role)
    db.commit()


def resolve_roles(db: Session, role_names: list[str]) -> list[Role]:
    """Resolve role names to existing Role rows. Unlike permissions, roles must
    already exist (they are managed exclusively via the role CRUD endpoints)."""
    roles = []
    for name in role_names:
        role = get_role_by_name(db, name)
        if not role:
            raise ValueError(f"Unknown role: {name}")
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
