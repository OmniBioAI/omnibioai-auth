"""BioRepository permissions (biorepo.read / biorepo.write / biorepo.admin)
are an additive vocabulary change only. Owner approval for this change was
explicitly scoped to "no changes to existing roles or permissions"; this file
locks that in:

1. every permission that existed before is byte-for-byte unchanged;
2. no default role list (org_admin, scientist, viewer) gains a biorepo.*
   permission, and those lists are exactly what they were;
3. no seeded role row and no issued JWT carries a biorepo.* permission;
4. the names are still assignable through the normal role APIs
   (is_known_permission), which is the only way anyone receives them.

Registry-shape assertions (scope, category, legacy flag) live in
test_permission_registry.py's BIOREPO_NAMES.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import hashlib
import json
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.core.permission_names import REGISTRY, is_known_permission
from app.db.models import Organization, OrganizationMembership, Role, User
from app.services import org_service, role_service
from app.services.auth_service import generate_tokens

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

BIOREPO = {"biorepo.read", "biorepo.write", "biorepo.admin"}

# sha256 of json.dumps({name: as_dict()}, sort_keys=True) over every registry
# entry on origin/main 75d3c83 (37 entries), taken before this change.
PRE_EXISTING_COUNT = 37
PRE_EXISTING_DIGEST = "e8c5db36667aa486bdff223c1f1babc72139a7c942bde3285c697c13de3c19fa"


def test_pre_existing_permissions_are_unchanged():
    """Every non-biorepo registry entry is exactly what it was before this change."""
    others = {name: perm.as_dict() for name, perm in REGISTRY.items() if name not in BIOREPO}
    assert len(others) == PRE_EXISTING_COUNT
    digest = hashlib.sha256(json.dumps(others, sort_keys=True).encode()).hexdigest()
    assert digest == PRE_EXISTING_DIGEST


def test_biorepo_names_are_registered_and_assignable():
    """The three names exist, so the role APIs accept them; nothing else grants them."""
    assert all(is_known_permission(name) for name in BIOREPO)


def test_default_role_lists_are_unchanged():
    """org_admin, scientist and viewer keep exactly their previous permissions."""
    assert org_service.ORG_ADMIN_PERMISSIONS == [
        "manage_org", "manage_teams", "manage_api_keys", "manage_billing", "manage_oauth_clients", "manage_sso",
        "workflow.read", "workflow.manage",
        "runs.read",
        "model.resolve_ownership",
        "model.read",
    ]
    assert org_service.SCIENTIST_PERMISSIONS == [
        "workflow.execute", "dataset.read", "model.use", "model.read", "workspace.launch",
        "runs.read",
    ]
    assert org_service.VIEWER_PERMISSIONS == ["dataset.read", "workflow.read"]


def test_no_seeded_role_holds_a_biorepo_permission(client):
    """Startup seeding (platform_admin, scientist, viewer, ...) grants no biorepo.* permission."""
    db = _DirectSession()
    try:
        names = {p.name for role in db.query(Role).all() for p in role.permissions}
    finally:
        db.close()
    assert names, "startup seeding should have created role rows"
    assert not names & BIOREPO


def _token_permissions(role_name, permissions):
    db = _DirectSession()
    try:
        user = User(email=f"biorepo-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
        db.add(user)
        db.flush()
        org = Organization(slug=f"biorepo-{uuid.uuid4().hex[:8]}", name="BioRepository permission test")
        db.add(org)
        db.flush()
        role = role_service.get_or_create_role(db, role_name, permissions)
        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role]))
        db.commit()
        db.refresh(user)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()
    return set(decode_token(access)["permissions"])


def test_default_role_tokens_carry_no_biorepo_permission(client):
    """Users holding each default org role get the same claims as before: no biorepo.*."""
    for role_name, permissions in (
        (org_service.ORG_ADMIN_ROLE, org_service.ORG_ADMIN_PERMISSIONS),
        (org_service.SCIENTIST_ROLE, org_service.SCIENTIST_PERMISSIONS),
        (org_service.VIEWER_ROLE, org_service.VIEWER_PERMISSIONS),
    ):
        perms = _token_permissions(role_name, permissions)
        assert set(permissions) <= perms
        assert not perms & BIOREPO, role_name


def test_an_explicitly_granted_role_does_carry_biorepo_read(client):
    """The only path to biorepo.*: an explicit role grant through the existing role model."""
    perms = _token_permissions(f"biorepo-reader-{uuid.uuid4().hex[:6]}", ["biorepo.read"])
    assert "biorepo.read" in perms
    assert not perms & {"biorepo.write", "biorepo.admin"}
