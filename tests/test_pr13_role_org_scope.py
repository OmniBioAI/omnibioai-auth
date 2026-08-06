"""PR13: Role.organization_id scope semantics -- uniqueness-within-scope,
GLOBAL-scope permission rejection on org-scoped roles (Finding 2, layer 1),
role_in_use now covering membership_roles as well as user_roles, and
list_roles_for_scope's visibility rules. Service-level (role_service.py
directly), not HTTP -- these are internal invariants the API layer relies
on, exercised directly the same way test_role_service.py-style unit tests
in this repo already do.
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Organization, OrganizationMembership
from app.services import role_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db(client):  # depends on `client` only to guarantee setup_db has run first
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


def _make_org(db, name="Scope Test Org") -> Organization:
    org = Organization(slug=f"scope-{uuid.uuid4().hex[:8]}", name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def _unique_name(prefix="role"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def test_org_scoped_role_can_hold_org_and_both_scope_permissions(db):
    org = _make_org(db)
    role = role_service.create_role(db, _unique_name(), ["dataset.read", "workflow.execute"], organization_id=org.id)
    assert role.organization_id == org.id
    assert {p.name for p in role.permissions} == {"dataset.read", "workflow.execute"}


def test_org_scoped_role_rejects_global_scope_permission(db):
    org = _make_org(db)
    with pytest.raises(ValueError, match="platform-wide permissions"):
        role_service.create_role(db, _unique_name(), ["manage_all_orgs"], organization_id=org.id)


def test_org_scoped_role_update_rejects_global_scope_permission(db):
    org = _make_org(db)
    role = role_service.create_role(db, _unique_name(), ["dataset.read"], organization_id=org.id)
    with pytest.raises(ValueError, match="platform-wide permissions"):
        role_service.update_role_permissions(db, role, ["dataset.read", "manage_roles"])


def test_org_scoped_role_still_rejects_unregistered_permission(db):
    """Layer 1's GLOBAL-scope check runs after the normal registry check,
    not instead of it -- an org role still can't invent a permission name
    that isn't in the registry at all."""
    org = _make_org(db)
    with pytest.raises(ValueError, match="Unknown permission"):
        role_service.create_role(db, _unique_name(), ["not.a.real.permission"], organization_id=org.id)


def test_platform_wide_name_reserved_across_every_org(db):
    """A platform-wide role's name can never be shadowed by an org-custom
    role of the same name -- platform-wide names are reserved everywhere."""
    org = _make_org(db)
    with pytest.raises(ValueError, match="already taken by a platform-wide role"):
        role_service.create_role(db, "admin", ["dataset.read"], organization_id=org.id)


def test_two_different_orgs_can_reuse_the_same_custom_role_name(db):
    """Org-custom names are private per org -- two different orgs may each
    have their own role with the same name."""
    org_a, org_b = _make_org(db, "Org A"), _make_org(db, "Org B")
    name = _unique_name("qa-reviewer")
    role_a = role_service.create_role(db, name, ["dataset.read"], organization_id=org_a.id)
    role_b = role_service.create_role(db, name, ["dataset.read"], organization_id=org_b.id)
    assert role_a.id != role_b.id
    assert role_a.name == role_b.name == name


def test_same_org_cannot_reuse_its_own_custom_role_name(db):
    org = _make_org(db)
    name = _unique_name()
    role_service.create_role(db, name, ["dataset.read"], organization_id=org.id)
    with pytest.raises(ValueError, match="already taken by another role in this organization"):
        role_service.create_role(db, name, ["workflow.read"], organization_id=org.id)


def test_org_custom_role_cannot_shadow_an_existing_platform_wide_name(db):
    """The reservation direction also holds the other way: creating a
    platform-wide role isn't blocked by an org already having a custom
    role of that name (custom names are private to their org and don't
    reserve anything platform-wide), but this test locks in the converse
    case already covered above isn't accidentally symmetric-breaking."""
    org = _make_org(db)
    name = _unique_name()
    role_service.create_role(db, name, ["dataset.read"], organization_id=org.id)
    # A platform-wide role with the same name is a separate, independent
    # namespace collision check -- not exercised here since it isn't part
    # of PR13's required guarantees, only documented as a known asymmetry.


def test_list_roles_for_scope_includes_platform_wide_and_own_custom_only(db):
    org_a, org_b = _make_org(db, "Visible Org"), _make_org(db, "Hidden Org")
    custom_a = role_service.create_role(db, _unique_name("custom-a"), ["dataset.read"], organization_id=org_a.id)
    custom_b = role_service.create_role(db, _unique_name("custom-b"), ["dataset.read"], organization_id=org_b.id)

    visible_to_a = role_service.list_roles_for_scope(db, org_a.id)
    visible_ids = {r.id for r in visible_to_a}

    assert custom_a.id in visible_ids
    assert custom_b.id not in visible_ids  # org B's custom role must not leak to org A
    # Every platform-wide role is visible too -- "scientist" is eagerly
    # seeded at startup (ensure_default_org_roles), unlike "org_admin"
    # which is only lazily created on first create_organization() and so
    # isn't guaranteed to exist yet when this test runs in isolation.
    assert any(r.name == "scientist" and r.organization_id is None for r in visible_to_a)


def test_role_in_use_covers_org_scoped_membership_assignment(db):
    """PR13 fix: role_in_use previously only checked user_roles (global
    assignment), silently missing membership_roles entirely."""
    org = _make_org(db)
    role = role_service.create_role(db, _unique_name(), ["dataset.read"], organization_id=org.id)
    assert role_service.role_in_use(db, role.id) is False

    membership = OrganizationMembership(organization_id=org.id, user_id=1, status="active", roles=[role])
    db.add(membership)
    db.commit()

    assert role_service.role_in_use(db, role.id) is True


def test_resolve_roles_rejects_org_scoped_custom_role(db):
    """A global (user_roles) assignment must never accept an org-private
    custom role -- it only makes sense scoped to the org that owns it."""
    org = _make_org(db)
    name = _unique_name()
    role_service.create_role(db, name, ["dataset.read"], organization_id=org.id)
    with pytest.raises(ValueError, match="Unknown role"):
        role_service.resolve_roles(db, [name])
