"""Model Registry read/use authorization split audit: model.read is a
new, narrower permission covering genuinely read-only Model Registry
catalog access (see permission_names.py's own entry for the full route
list this gates in omnibioai-model-registry). Granted to scientist and
org_admin, mirroring workflow.read/runs.read's exact precedent ("reading
vs. doing" split) -- see org_service.py's SCIENTIST_PERMISSIONS/
ORG_ADMIN_PERMISSIONS for the grant itself and their own inline comments
for the reasoning.

Deliberately NOT granted to platform_admin: that role has never held any
org-scoped resource permission (workflow.read, dataset.read, runs.read,
or model.use) for any resource -- ensure_platform_admin_role only ever
grants manage_all_orgs, and every platform-scoped route already does its
own separate require_permission(MANAGE_ALL_ORGS)/_require_platform_admin
check rather than relying on org-scoped resource permissions at all.
Adding model.read there would be a new pattern, not filling an existing
gap -- this file locks in that decision so it isn't silently reversed by
some future PR "helpively" adding it.

Permission-catalog shape (registered, BOTH-scoped, not legacy, not
marked reserved) is covered by test_permission_registry.py's
MODEL_REGISTRY_READ_NAMES assertions; this file covers the role-grant and
resulting-JWT-claim side instead, mirroring test_pr13_jwt_permission_
merge.py's/test_model_resolve_ownership_permission.py's own conventions.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import Organization, OrganizationMembership, Role, User
from app.services import org_service, role_service
from app.services.auth_service import generate_tokens

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _make_user(db, email=None) -> User:
    user = User(email=email or f"model-read-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_active_membership(db, user: User, role_name: str) -> OrganizationMembership:
    org = Organization(slug=f"model-read-{uuid.uuid4().hex[:8]}", name="Model Read Split Org")
    db.add(org)
    db.flush()
    role = role_service.get_role_by_name(db, role_name)
    assert role is not None, f"{role_name!r} should have been seeded at startup"
    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role])
    db.add(membership)
    db.commit()
    return membership


# ── 1. Static role/permission-list assertions ────────────────────────────────

def test_scientist_permission_list_includes_model_read_and_model_use():
    assert "model.read" in org_service.SCIENTIST_PERMISSIONS
    assert "model.use" in org_service.SCIENTIST_PERMISSIONS


def test_org_admin_permission_list_includes_model_read():
    assert "model.read" in org_service.ORG_ADMIN_PERMISSIONS
    # Unchanged: org_admin must NOT hold model.use, the same "operator
    # capability, not org-administration" boundary workflow.execute is
    # kept off this list for.
    assert "model.use" not in org_service.ORG_ADMIN_PERMISSIONS


def test_viewer_permission_list_unchanged_no_model_read():
    # VIEWER_PERMISSIONS was explicitly out of this audit's scope (the
    # task named scientist/org_admin only) -- confirms it wasn't touched
    # as a side effect.
    assert "model.read" not in org_service.VIEWER_PERMISSIONS
    assert org_service.VIEWER_PERMISSIONS == ["dataset.read", "workflow.read"]


# ── 2. platform_admin does NOT receive model.read (explicit decision) ────────

def test_platform_admin_role_does_not_include_model_read(client):
    """`client` fixture (conftest.py) already triggers app.main's startup
    sequence, which runs ensure_platform_admin_role -- the platform_admin
    Role row exists by the time this test runs."""
    db = _DirectSession()
    try:
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        perm_names = {p.name for p in role.permissions}
    finally:
        db.close()
    assert perm_names == {"manage_all_orgs"}
    assert "model.read" not in perm_names
    assert "model.use" not in perm_names


# ── 3. Resulting JWT claims ────────────────────────────────────────────────

def test_scientist_org_role_jwt_includes_model_read():
    db = _DirectSession()
    try:
        user = _make_user(db)
        _make_active_membership(db, user, "scientist")
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert {"model.use", "model.read"} <= perms


def test_org_admin_role_jwt_includes_model_read_not_model_use():
    # Unlike scientist/viewer (eagerly seeded at every startup by
    # ensure_default_org_roles), org_admin is only ever created as a side
    # effect of create_organization() -- see ensure_org_admin_permissions'
    # own docstring ("no org has been created yet -- nothing to top up").
    # get_or_create_role with ORG_ADMIN_PERMISSIONS mirrors
    # test_model_resolve_ownership_permission.py's own _org_admin_role
    # helper for the identical reason.
    db = _DirectSession()
    try:
        user = _make_user(db)
        org = Organization(slug=f"model-read-orgadmin-{uuid.uuid4().hex[:8]}", name="Model Read Split Org Admin")
        db.add(org)
        db.flush()
        role = role_service.get_or_create_role(db, org_service.ORG_ADMIN_ROLE, org_service.ORG_ADMIN_PERMISSIONS)
        membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role])
        db.add(membership)
        db.commit()
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert "model.read" in perms
    assert "model.use" not in perms


def test_pure_platform_admin_jwt_has_neither_model_read_nor_model_use(client):
    """A platform_admin with no separate org membership at all -- the
    scenario this audit's report flags as a known, unchanged residual
    gap: such an operator still cannot see the Model Registry catalog
    through the Admin Console after this change, exactly as they
    couldn't before it (this was never a regression this audit
    introduced -- platform_admin never held model.use either)."""
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None
        user.roles.append(role)
        db.commit()
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert "manage_all_orgs" in perms
    assert "model.read" not in perms
    assert "model.use" not in perms
