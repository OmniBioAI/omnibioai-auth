"""omnibioai-billing Stripe payment-method integration: registers
`manage_billing` as an org-scoped, legacy-style permission in the
Permission Registry (app/core/permission_names.py) and grants it to the
org_admin role only (app/services/org_service.py's ORG_ADMIN_PERMISSIONS),
mirroring manage_api_keys's exact shape -- same scope (ORG), same category
(ORGANIZATION), same legacy=True, same "org administration" grant --
immediately next to it in both files.

manage_billing gates omnibioai-billing's two mutating payment-method
endpoints (POST .../payment-method/setup-session and POST
.../portal-session); the GET endpoint remains readable by any org member.
See permission_names.py's registry entry for why this is a separate,
underscore-named entry rather than activating the already-reserved,
dot-notation "billing.manage" FUTURE_NAMES placeholder.

Covers the same focused checklist test_model_resolve_ownership_permission.py
established for the previous org_admin-only permission addition:
  1. manage_billing is registered and recognized.
  2. A principal without manage_billing does not receive it.
  3. A principal explicitly granted manage_billing (via org_admin) receives it.
  4. The permission is grantable through the normal role-CRUD surface too.
  5. ORG_ADMIN_PERMISSIONS is a pure addition; nothing else changed.
  6. The startup top-up (ensure_org_admin_permissions) retroactively grants
     manage_billing to a pre-existing org_admin role without disturbing
     anything else on it.
  7. Existing permission-registry tests remain passing -- see the
     companion updates in test_permission_registry.py and
     test_platform_permissions_api.py (updated LEGACY_NAMES/ORG_LEGACY_NAMES
     sets and registry-size counts), both updated in the same change as
     this file.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.core.permission_names import (
    REGISTRY,
    PermissionCategory,
    PermissionScope,
    is_known_permission,
)
from app.db.models import Organization, OrganizationMembership, User
from app.services import org_service, role_service
from app.services.auth_service import generate_tokens

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _make_user(db, email=None) -> User:
    user = User(
        email=email or f"manage-billing-{uuid.uuid4().hex[:8]}@omnibioai.test",
        hashed_password=None, status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_active_membership(db, user: User, role) -> OrganizationMembership:
    org = Organization(slug=f"manage-billing-{uuid.uuid4().hex[:8]}", name="Manage Billing Test Org")
    db.add(org)
    db.flush()
    membership = OrganizationMembership(
        organization_id=org.id, user_id=user.id, status="active", roles=[role],
    )
    db.add(membership)
    db.commit()
    return membership


def _org_admin_role(db):
    """Robust, order-independent way to get an org_admin Role row that
    definitely carries the current ORG_ADMIN_PERMISSIONS (including
    manage_billing) -- doesn't depend on some other test file having
    already created an org first. Mirrors
    test_model_resolve_ownership_permission.py's own _org_admin_role
    helper for the identical reason."""
    role = role_service.get_or_create_role(db, org_service.ORG_ADMIN_ROLE, org_service.ORG_ADMIN_PERMISSIONS)
    org_service.ensure_org_admin_permissions(db)
    db.refresh(role)
    return role


def _member_role(db):
    """A role with no administrative permissions at all, standing in for
    an ordinary org member who can read billing state but not manage it."""
    return role_service.get_or_create_role(db, "member_mb_check", [])


# ── 1. Registered and recognized ────────────────────────────────────────────

def test_manage_billing_is_registered_and_recognized():
    """manage_billing is a known, legacy, ORG-scoped, ORGANIZATION-category permission, matching
    manage_api_keys's exact shape.
    """
    assert is_known_permission("manage_billing")
    entry = REGISTRY["manage_billing"]
    assert entry.resource == "billing"
    assert entry.action == "manage"
    assert entry.legacy is True
    assert entry.scope == PermissionScope.ORG
    assert entry.category == PermissionCategory.ORGANIZATION

    api_keys = REGISTRY["manage_api_keys"]
    assert entry.legacy == api_keys.legacy
    assert entry.scope == api_keys.scope
    assert entry.category == api_keys.category


def test_manage_billing_is_distinct_from_reserved_billing_manage_placeholder():
    """manage_billing is a separate, real, ORG-scoped entry -- not the same name as, or an alias
    for, the pre-existing reserved BOTH-scoped "billing.manage" placeholder.
    """
    assert "billing.manage" in REGISTRY
    assert REGISTRY["billing.manage"].scope == PermissionScope.BOTH
    assert REGISTRY["billing.manage"].legacy is False
    assert REGISTRY["manage_billing"].scope == PermissionScope.ORG
    assert REGISTRY["manage_billing"] != REGISTRY["billing.manage"]


# ── 2 & 3. Grant / no-grant behavior ─────────────────────────────────────────

def test_principal_without_permission_does_not_receive_it(client):
    """A member whose role grants nothing administrative does not receive manage_billing."""
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _member_role(db)
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "manage_billing" not in perms


def test_principal_explicitly_granted_permission_receives_it(client):
    """A member whose role is org_admin receives manage_billing in their effective permissions."""
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _org_admin_role(db)
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "manage_billing" in perms
    assert "manage_api_keys" in perms  # same role, same grant shape


def test_custom_role_can_be_granted_the_permission_via_role_crud(client):
    """Confirms the permission is grantable through the normal role-CRUD surface too, not just the
    org_admin seed.
    """
    db = _DirectSession()
    try:
        role = role_service.create_role(
            db, f"manage-billing-custom-{uuid.uuid4().hex[:6]}", ["manage_billing"],
        )
        assert "manage_billing" in {p.name for p in role.permissions}
    finally:
        db.close()


def test_unknown_permission_name_still_rejected(client):
    """Creating a role with an unknown permission name still raises ValueError, confirming
    manage_billing's addition to the registry didn't loosen validation."""
    db = _DirectSession()
    try:
        with pytest.raises(ValueError, match="Unknown permission"):
            role_service.create_role(db, f"manage-billing-bad-{uuid.uuid4().hex[:6]}", ["manage_billings"])
    finally:
        db.close()


# ── 5. ORG_ADMIN_PERMISSIONS is additive only ────────────────────────────────

def test_org_admin_permission_list_is_additive_only():
    """ORG_ADMIN_PERMISSIONS still contains every previously established permission and additionally
    includes manage_billing.
    """
    preexisting = {
        "manage_org", "manage_teams", "manage_api_keys", "manage_oauth_clients",
        "manage_sso", "workflow.read", "workflow.manage", "runs.read",
        "model.resolve_ownership", "model.read",
    }
    assert preexisting <= set(org_service.ORG_ADMIN_PERMISSIONS)
    assert "manage_billing" in org_service.ORG_ADMIN_PERMISSIONS


def test_org_admin_role_still_grants_manage_org_alongside_new_permission(client):
    """An org_admin member's permissions include manage_org and manage_billing but not the
    platform-scoped manage_all_orgs.
    """
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _org_admin_role(db)
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "manage_org" in perms
    assert "manage_billing" in perms
    assert "manage_all_orgs" not in perms  # still not platform-scoped


# ── 6. Startup top-up retroactively grants it ────────────────────────────────

def test_ensure_org_admin_permissions_tops_up_manage_billing(client):
    """Simulates a pre-this-PR deployment: an org_admin Role that already
    exists with only an older permission set. The startup top-up must add
    manage_billing without disturbing anything else already on the role
    (including a permission an operator added by hand outside
    ORG_ADMIN_PERMISSIONS entirely) -- same contract
    test_oauth_clients.py's test_ensure_org_admin_permissions_tops_up_existing_role_additively
    established for manage_oauth_clients.
    """
    db = _DirectSession()
    try:
        role = role_service.get_or_create_role(db, org_service.ORG_ADMIN_ROLE, ["manage_org"])
        db.commit()
        # update_role_permissions validates against the Permission
        # Registry, so the "operator added something by hand" stand-in
        # must be a registered (if unrelated to ORG_ADMIN_PERMISSIONS) name
        # rather than an arbitrary string.
        role_service.update_role_permissions(db, role, ["manage_org", "workflow.execute"])

        org_service.ensure_org_admin_permissions(db)

        db.refresh(role)
        names = {p.name for p in role.permissions}
        assert "manage_billing" in names
        assert "workflow.execute" in names  # untouched, not removed
    finally:
        db.close()
