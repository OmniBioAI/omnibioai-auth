"""IAM registration/grant task for omnibioai-model-registry's Phase 2E
legacy-ownership resolution feature: registers `model.resolve_ownership`
as an independent, non-legacy, BOTH-scoped permission in the registry
(app/core/permission_names.py) and grants it to the org_admin role only
(app/services/org_service.py's ORG_ADMIN_PERMISSIONS), mirroring the
established workflow.manage/runs.read/manage_teams precedent for
"administer this org's own resources" capabilities.

model.resolve_ownership is deliberately NOT added to SCIENTIST_PERMISSIONS
(which carries model.use) -- it authorizes resolving a legacy_unowned
Model Registry model's ownership to the caller's own org, a materially
more privileged, ownership-reassignment-adjacent action than ordinary
model read/write access. See permission_names.py's registry entry and
org_service.py's ORG_ADMIN_PERMISSIONS for the full design rationale.

Covers the full focused checklist:
  1. model.resolve_ownership is registered and recognized.
  2. Invalid permission names still fail the existing validator.
  3. A principal without model.resolve_ownership does not receive it.
  4. A principal explicitly granted model.resolve_ownership receives it.
  5. model.use does not unexpectedly become equivalent to
     model.resolve_ownership (checked in both directions).
  6. Existing model.use authorization behavior is unchanged.
  7. Existing organization/UserContext (org_admin role) behavior is
     unchanged aside from the one additive grant.
  8. No client-controlled organization identity is introduced.
  9. Existing permission-registry tests remain passing -- see the
     companion updates in test_permission_registry.py (new
     MODEL_REGISTRY_OWNERSHIP_NAMES group) and
     test_platform_permissions_api.py (updated counts).
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
    is_valid_permission_format,
)
from app.db.models import Organization, OrganizationMembership, User
from app.services import org_service, role_service
from app.services.auth_service import generate_tokens

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _make_user(db, email=None) -> User:
    user = User(
        email=email or f"resolve-own-{uuid.uuid4().hex[:8]}@omnibioai.test",
        hashed_password=None, status="active",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_active_membership(db, user: User, role) -> OrganizationMembership:
    org = Organization(slug=f"resolve-own-{uuid.uuid4().hex[:8]}", name="Resolve Ownership Test Org")
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
    model.resolve_ownership) -- doesn't depend on some other test file
    having already created an org first (test_pr13_jwt_permission_merge.py
    relies on that ordering; this file deliberately doesn't). Mirrors
    test_oauth_clients.py's ensure_org_admin_permissions top-up pattern.
    """
    role = role_service.get_or_create_role(db, org_service.ORG_ADMIN_ROLE, org_service.ORG_ADMIN_PERMISSIONS)
    org_service.ensure_org_admin_permissions(db)
    db.refresh(role)
    return role


def _scientist_role(db):
    return role_service.get_or_create_role(db, "scientist_rop_check", org_service.SCIENTIST_PERMISSIONS)


# ── 1. Registered and recognized ────────────────────────────────────────────

def test_model_resolve_ownership_is_registered_and_recognized():
    assert is_known_permission("model.resolve_ownership")
    entry = REGISTRY["model.resolve_ownership"]
    assert entry.resource == "model"
    assert entry.action == "resolve_ownership"
    assert entry.legacy is False
    assert entry.scope == PermissionScope.BOTH
    assert entry.category == PermissionCategory.MODEL
    assert is_valid_permission_format("model.resolve_ownership")


# ── 2. Invalid permission names still rejected ──────────────────────────────

def test_two_dot_variant_fails_format_validation():
    # The originally-discussed name (model.ownership.resolve) has two dots
    # and must fail the single-dot resource.action validator -- confirming
    # why model.resolve_ownership (one dot) was used instead.
    assert not is_valid_permission_format("model.ownership.resolve")
    assert not is_known_permission("model.ownership.resolve")


def test_role_creation_still_rejects_unknown_permission_names(client):
    db = _DirectSession()
    try:
        with pytest.raises(ValueError, match="Unknown permission"):
            role_service.create_role(db, f"resolve-own-bad-{uuid.uuid4().hex[:6]}", ["model.ownership.resolve"])
    finally:
        db.close()


# ── 3 & 4. Grant / no-grant behavior ─────────────────────────────────────────

def test_principal_without_permission_does_not_receive_it(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _scientist_role(db)
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "model.use" in perms
    assert "model.resolve_ownership" not in perms


def test_principal_explicitly_granted_permission_receives_it(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _org_admin_role(db)
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "model.resolve_ownership" in perms


def test_custom_role_can_be_granted_the_permission_via_role_crud(client):
    """Confirms the permission is grantable through the normal role-CRUD
    surface too, not just the org_admin seed -- an operator could grant it
    to any custom role via POST/PUT /roles without any code change."""
    db = _DirectSession()
    try:
        role = role_service.create_role(
            db, f"resolve-own-custom-{uuid.uuid4().hex[:6]}", ["model.resolve_ownership"],
        )
        assert "model.resolve_ownership" in {p.name for p in role.permissions}
    finally:
        db.close()


# ── 5. model.use and model.resolve_ownership are independent ────────────────

def test_model_use_does_not_imply_model_resolve_ownership(client):
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = _scientist_role(db)  # holds model.use, not model.resolve_ownership
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "model.use" in perms
    assert "model.resolve_ownership" not in perms


def test_model_resolve_ownership_does_not_imply_model_use(client):
    """The converse: a principal granted only model.resolve_ownership (via
    a custom role, not org_admin, which also happens to carry other
    permissions) does not incidentally gain model.use either."""
    db = _DirectSession()
    try:
        user = _make_user(db)
        role = role_service.create_role(
            db, f"resolve-own-only-{uuid.uuid4().hex[:6]}", ["model.resolve_ownership"],
        )
        _make_active_membership(db, user, role)
        access, _ = generate_tokens(db, user, auth_method="password")
    finally:
        db.close()

    perms = set(decode_token(access)["permissions"])
    assert "model.resolve_ownership" in perms
    assert "model.use" not in perms


# ── 6. Existing model.use authorization behavior unchanged ──────────────────

def test_existing_scientist_permission_set_unchanged():
    # SCIENTIST_PERMISSIONS (the role that carries model.use) must not have
    # gained model.resolve_ownership as a side effect of this change.
    # model.read was added later by the Model Registry read/use
    # authorization split audit (a real, intentional addition to this
    # list, unrelated to model.resolve_ownership) -- included here so this
    # assertion tracks the actual current list rather than pinning a
    # stale snapshot.
    assert org_service.SCIENTIST_PERMISSIONS == ["workflow.execute", "dataset.read", "model.use", "model.read"]
    assert "model.resolve_ownership" not in org_service.SCIENTIST_PERMISSIONS


# ── 7. Existing organization/UserContext behavior unchanged ─────────────────

def test_org_admin_permission_list_is_additive_only():
    # model.resolve_ownership must be a pure addition to ORG_ADMIN_PERMISSIONS
    # -- every permission that was already there (the established
    # PR13/Phase-2 precedent set) must still be present.
    preexisting = {
        "manage_org", "manage_teams", "manage_api_keys", "manage_oauth_clients",
        "manage_sso", "workflow.read", "workflow.manage", "runs.read",
    }
    assert preexisting <= set(org_service.ORG_ADMIN_PERMISSIONS)
    assert "model.resolve_ownership" in org_service.ORG_ADMIN_PERMISSIONS


def test_org_admin_role_still_grants_manage_org_alongside_new_permission(client):
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
    assert "model.resolve_ownership" in perms
    assert "manage_all_orgs" not in perms  # still not platform-scoped


# ── 8. No client-controlled organization identity introduced ────────────────

def test_permission_registry_entry_carries_no_organization_field():
    # The registry entry itself is pure vocabulary -- no organization_id or
    # any other client-suppliable identity field is part of a PermissionDef.
    entry = REGISTRY["model.resolve_ownership"]
    d = entry.as_dict()
    assert "organization_id" not in d
    assert set(d.keys()) == {
        "name", "resource", "action", "scope", "category",
        "description", "legacy", "deprecated", "deprecated_reason",
    }


# ── 9. Existing permission-registry tests remain passing ────────────────────
# Covered by tests/test_permission_registry.py (new
# MODEL_REGISTRY_OWNERSHIP_NAMES group, updated exhaustive-union and
# registry_stats assertions) and tests/test_platform_permissions_api.py
# (updated len(REGISTRY) and FUTURE_NAMES-set counts), both updated in the
# same change as this file -- run alongside it, not duplicated here.
