import os
import secrets
from datetime import datetime

from app.db.models import Organization, Permission, Role, User
from app.core.permission_names import (
    PLATFORM_MANAGE_CONTENT,
    PLATFORM_MANAGE_CRON,
    PLATFORM_MANAGE_INFRA,
)
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

    # Phase 2 PR5: deliberately a distinct global permission, not a reuse
    # of "manage_sso" (which already means something different -- an
    # org-scoped grant checked live via require_org_permission, not this
    # JWT-claim-based global check). The SSO break-glass override is meant
    # to be usable by this platform's own bootstrap admin even when an
    # org's own admin is the one locked out (or untrusted), so it's kept
    # separate from any org-level grant entirely.
    override_sso_perm = db.query(Permission).filter(Permission.name == "override_sso_enforcement").first()
    if not override_sso_perm:
        override_sso_perm = Permission(name="override_sso_enforcement")
        db.add(override_sso_perm)
        db.flush()

    # PR3D: gates omnibioai-control-center's docker/services/summary/config
    # routers via require_iam_permission -- replaces that repo's former
    # hardcoded "admin" in roles check. Same get-or-create/append-if-missing
    # shape as every permission above; kept as three separate permissions
    # (rather than folded into an existing one) so each of Control Center's
    # operational surfaces -- infra, cron, content -- can be granted
    # independently of the others in a future, more finely-scoped role.
    manage_infra_perm = db.query(Permission).filter(Permission.name == PLATFORM_MANAGE_INFRA).first()
    if not manage_infra_perm:
        manage_infra_perm = Permission(name=PLATFORM_MANAGE_INFRA)
        db.add(manage_infra_perm)
        db.flush()

    manage_cron_perm = db.query(Permission).filter(Permission.name == PLATFORM_MANAGE_CRON).first()
    if not manage_cron_perm:
        manage_cron_perm = Permission(name=PLATFORM_MANAGE_CRON)
        db.add(manage_cron_perm)
        db.flush()

    manage_content_perm = db.query(Permission).filter(Permission.name == PLATFORM_MANAGE_CONTENT).first()
    if not manage_content_perm:
        manage_content_perm = Permission(name=PLATFORM_MANAGE_CONTENT)
        db.add(manage_content_perm)
        db.flush()

    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(
            name="admin",
            permissions=[
                manage_roles_perm,
                manage_licenses_perm,
                manage_config_perm,
                override_sso_perm,
                manage_infra_perm,
                manage_cron_perm,
                manage_content_perm,
            ],
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
        if override_sso_perm not in admin_role.permissions:
            admin_role.permissions.append(override_sso_perm)
        if manage_infra_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_infra_perm)
        if manage_cron_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_cron_perm)
        if manage_content_perm not in admin_role.permissions:
            admin_role.permissions.append(manage_content_perm)

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


def ensure_platform_admin_role(db):
    """Phase 3 PR0.4: `manage_all_orgs` is a distinct, narrowly-scoped
    global permission -- not folded into the existing "admin" role's
    manage_roles/manage_licenses/manage_config/override_sso_enforcement
    set. It lives on its own new "platform_admin" role so an operator can
    grant cross-tenant organization access independently of every other
    admin capability, and so app/rbac.py's
    require_org_permission_or_platform_admin checks this permission
    string, never the literal role name "platform_admin" -- the role is
    simply "whatever holds this permission today," not something
    authorization code hardcodes (same reasoning Phase 2 PR5 applied to
    override_sso_enforcement).

    Idempotent and purely additive, mirroring create_admin's own pattern
    above: never modifies the existing "admin" or "org_admin" roles, and
    does not assign this role to any user -- not even the bootstrap
    admin@omnibioai account. Cross-tenant access is deliberately opt-in
    per operator, not a side effect of already holding "admin".
    """
    manage_all_orgs_perm = db.query(Permission).filter(Permission.name == "manage_all_orgs").first()
    if not manage_all_orgs_perm:
        manage_all_orgs_perm = Permission(name="manage_all_orgs")
        db.add(manage_all_orgs_perm)
        db.flush()

    platform_admin_role = db.query(Role).filter(Role.name == "platform_admin").first()
    if not platform_admin_role:
        platform_admin_role = Role(name="platform_admin", permissions=[manage_all_orgs_perm])
        db.add(platform_admin_role)
    elif manage_all_orgs_perm not in platform_admin_role.permissions:
        platform_admin_role.permissions.append(manage_all_orgs_perm)

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