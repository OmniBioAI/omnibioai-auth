from sqlalchemy.orm import Session

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


def create_role(db: Session, name: str, permission_names: list[str]) -> Role:
    role = Role(name=name, permissions=_get_or_create_permissions(db, permission_names))
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


def update_role_permissions(db: Session, role: Role, permission_names: list[str]) -> Role:
    role.permissions = _get_or_create_permissions(db, permission_names)
    db.commit()
    db.refresh(role)
    return role


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
