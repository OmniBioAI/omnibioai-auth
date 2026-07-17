from app.db.models import Permission, Role, User
from app.core.security import hash_password


def create_admin(db):
    manage_roles_perm = db.query(Permission).filter(Permission.name == "manage_roles").first()
    if not manage_roles_perm:
        manage_roles_perm = Permission(name="manage_roles")
        db.add(manage_roles_perm)
        db.flush()

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin", permissions=[manage_roles_perm])
        db.add(admin_role)
        db.flush()
    elif manage_roles_perm not in admin_role.permissions:
        admin_role.permissions.append(manage_roles_perm)

    admin = db.query(User).filter(User.email == "admin@omnibioai").first()
    if not admin:
        admin = User(
            email="admin@omnibioai",
            hashed_password=hash_password("admin"),
            status="active"
        )
        db.add(admin)
        db.flush()

    if admin_role not in admin.roles:
        admin.roles.append(admin_role)

    db.commit()