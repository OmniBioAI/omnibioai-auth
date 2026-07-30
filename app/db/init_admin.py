import os
import secrets

from app.db.models import Permission, Role, User
from app.core.security import hash_password
from app.services.role_service import get_or_create_role


def create_admin(db):
    # Baseline role for regular signups (register/license/oauth) -- see
    # role_service.assign_default_role, called from each of those sites.
    get_or_create_role(db, "user")

    manage_roles_perm = db.query(Permission).filter(Permission.name == "manage_roles").first()
    if not manage_roles_perm:
        manage_roles_perm = Permission(name="manage_roles")
        db.add(manage_roles_perm)
        db.flush()

    manage_licenses_perm = db.query(Permission).filter(Permission.name == "manage_licenses").first()
    if not manage_licenses_perm:
        manage_licenses_perm = Permission(name="manage_licenses")
        db.add(manage_licenses_perm)
        db.flush()

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin", permissions=[manage_roles_perm, manage_licenses_perm])
        db.add(admin_role)
        db.flush()
    else:
        if manage_roles_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_roles_perm)
        if manage_licenses_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_licenses_perm)

    admin = db.query(User).filter(User.email == "admin@omnibioai").first()
    if not admin:
        # No hardcoded default password: an operator-supplied
        # ADMIN_BOOTSTRAP_PASSWORD is used if set (e.g. scripted deployments
        # pulling from a secret store); otherwise a random password is
        # generated here and printed to stdout ONCE, at creation time only —
        # never persisted in code or committed anywhere. This only runs the
        # first time this account is created (guarded by the `if not admin`
        # above), so it does not reprint/reset on every subsequent startup.
        password = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")
        generated = password is None
        if generated:
            password = secrets.token_urlsafe(24)

        admin = User(
            email="admin@omnibioai",
            hashed_password=hash_password(password),
            status="active"
        )
        db.add(admin)
        db.flush()

        if generated:
            print(
                "=" * 72 + "\n"
                "First-run admin bootstrap: created admin@omnibioai with a\n"
                f"randomly generated password:\n\n    {password}\n\n"
                "Log in and rotate this immediately -- it is not stored anywhere\n"
                "except this one-time startup log line. Set ADMIN_BOOTSTRAP_PASSWORD\n"
                "before first startup instead if you want to control it directly.\n"
                + "=" * 72,
                flush=True,
            )

    if admin_role not in admin.roles:
        admin.roles.append(admin_role)

    db.commit()