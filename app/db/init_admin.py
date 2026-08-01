import os
import secrets
from datetime import datetime

from app.db.models import Organization, Permission, Role, User
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

    # Distinct from manage_roles/manage_licenses -- gates webstudio's global
    # LLM/cloud/directory config (config_service.py), a separate concern
    # from role or license management. Kept its own permission so a future
    # role could manage config without also managing roles/licenses.
    manage_config_perm = db.query(Permission).filter(Permission.name == "manage_config").first()
    if not manage_config_perm:
        manage_config_perm = Permission(name="manage_config")
        db.add(manage_config_perm)
        db.flush()

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(
            name="admin",
            permissions=[manage_roles_perm, manage_licenses_perm, manage_config_perm],
        )
        db.add(admin_role)
        db.flush()
    else:
        if manage_roles_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_roles_perm)
        if manage_licenses_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_licenses_perm)
        if manage_config_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_config_perm)

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


def ensure_default_organization(db):
    """Idempotent, mirrors the `if not admin:` guard above. Creates an
    inert org shell only -- no existing user (not even admin@omnibioai) is
    added as a member here. Organization membership is a brand-new concept
    with nothing else in the app reading or writing it yet; backfilling
    every existing user's global role assignment into this org is Phase 1
    PR3's job, not this one, so real accounts intentionally have zero
    organization_memberships rows until then.
    """
    org = db.query(Organization).filter(Organization.slug == "default").first()
    if not org:
        admin = db.query(User).filter(User.email == "admin@omnibioai").first()
        org = Organization(
            slug="default",
            name="Default Organization",
            created_by_user_id=admin.id if admin else None,
            created_at=datetime.utcnow(),
        )
        db.add(org)
        db.commit()