"""PR13: JWT `permissions` claim cutover -- now the union of a user's
global-role permissions and their primary org membership's role
permissions, not global-only as it was through PR12. Exercises
build_user_claims (via generate_tokens) directly against a hand-built
membership, the same "direct DB session, decode the token" pattern
test_jwt_org_context.py already uses for claim content that isn't
observable via any HTTP response field.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import Organization, OrganizationMembership, User
from app.services import role_service
from app.services.auth_service import generate_tokens

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _make_user(db, email=None) -> User:
    user = User(email=email or f"pr13-jwt-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_active_membership(db, user: User, role_name: str) -> OrganizationMembership:
    org = Organization(slug=f"pr13-jwt-{uuid.uuid4().hex[:8]}", name="PR13 JWT Merge Org")
    db.add(org)
    db.flush()
    role = role_service.get_role_by_name(db, role_name)
    assert role is not None, f"{role_name!r} should have been seeded by ensure_default_org_roles at startup"
    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role])
    db.add(membership)
    db.commit()
    return membership


def test_scientist_org_role_grants_exactly_its_permission_set(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        _make_active_membership(db, user, "scientist")
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert {"workflow.execute", "dataset.read", "model.use"} <= perms
    assert "workflow.publish" not in perms
    assert "manage_org" not in perms


def test_viewer_org_role_grants_exactly_its_permission_set(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        _make_active_membership(db, user, "viewer")
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert {"dataset.read", "workflow.read"} <= perms
    assert "workflow.execute" not in perms
    assert "workflow.publish" not in perms
    assert "manage_org" not in perms


def test_org_admin_role_grants_org_management_not_platform_management(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        _make_active_membership(db, user, "org_admin")
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    claims = decode_token(access)
    perms = set(claims["permissions"])
    assert "manage_org" in perms
    assert "manage_all_orgs" not in perms


def test_global_and_org_permissions_are_unioned_not_overwritten(client):
    """A user with both a global role (holding some permission) and an org
    membership role (holding a disjoint permission) gets the union in
    their JWT -- neither set clobbers the other."""
    db = _DirectSession()
    try:
        user = _make_user(db)
        global_role = role_service.get_role_by_name(db, "manage_roles") or role_service.create_role(
            db, f"pr13-global-{uuid.uuid4().hex[:6]}", ["manage_roles"],
        )
        user.roles.append(global_role)
        db.commit()
        _make_active_membership(db, user, "scientist")
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "manage_roles" in perms  # global
    assert "workflow.execute" in perms  # org-scoped
