"""Phase 1 PR3: permission_parity.check_and_log -- observational drift
detection between the legacy global permission set and the new org-scoped
one. Purely a logging signal during the transition; must never silently
swallow a mismatch, and must never change what's actually enforced.
"""

import logging
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Organization, OrganizationMembership, Role, User
from app.services import permission_parity, role_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db():
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


def _make_user(db, roles=None):
    user = User(email=f"parity-{uuid.uuid4().hex[:8]}@omnibioai.test", hashed_password=None, status="active")
    if roles:
        user.roles = roles
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_org(db):
    org = Organization(slug=f"parity-org-{uuid.uuid4().hex[:8]}", name="Parity Test Org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def test_matching_permissions_reports_no_mismatch(db):
    role = role_service.get_or_create_role(db, f"parity-match-{uuid.uuid4().hex[:8]}", ["read:samples"])
    db.commit()
    user = _make_user(db, roles=[role])
    org = _make_org(db)

    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role])
    db.add(membership)
    db.commit()
    db.refresh(membership)

    result = permission_parity.check_and_log(user, ["read:samples"], membership)
    assert result["matches"] is True
    assert result["missing_in_org"] == []
    assert result["extra_in_org"] == []


def test_mismatch_detected_and_not_silently_ignored(db, caplog):
    global_role = role_service.get_or_create_role(db, f"parity-global-{uuid.uuid4().hex[:8]}", ["manage_roles"])
    org_role = role_service.get_or_create_role(db, f"parity-orgside-{uuid.uuid4().hex[:8]}", ["manage_teams"])
    db.commit()

    user = _make_user(db, roles=[global_role])
    org = _make_org(db)
    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[org_role])
    db.add(membership)
    db.commit()
    db.refresh(membership)

    with caplog.at_level(logging.WARNING, logger="omnibioai.auth.permission_parity"):
        result = permission_parity.check_and_log(user, ["manage_roles"], membership)

    assert result["matches"] is False
    assert result["missing_in_org"] == ["manage_roles"]
    assert result["extra_in_org"] == ["manage_teams"]
    # The actual "do not silently ignore" assertion: a warning was logged,
    # not just returned in the result dict for a caller who might discard it.
    assert any("permission_parity_mismatch" in r.message for r in caplog.records)
    assert any(str(user.id) in r.message for r in caplog.records)


def test_generate_tokens_triggers_parity_check_for_org_members(client, caplog):
    """Integration-level: logging in as a user with an org membership whose
    permissions have been made to diverge must actually surface the
    warning through the real generate_tokens call path, not just when
    check_and_log is called directly."""
    db = _DirectSession()
    try:
        global_role = role_service.get_or_create_role(
            db, f"parity-integ-global-{uuid.uuid4().hex[:8]}", ["manage_config"]
        )
        db.commit()
        email = f"parity-integ-{uuid.uuid4().hex[:8]}@omnibioai.test"
        from app.core.security import hash_password

        user = User(email=email, hashed_password=hash_password("TestPassword123!"), status="active", roles=[global_role])
        db.add(user)
        db.commit()
        db.refresh(user)

        org = _make_org(db)
        # Deliberately empty-permission org role -- guarantees a mismatch
        # against the user's real global "manage_config" permission.
        empty_role = role_service.get_or_create_role(db, f"parity-integ-empty-{uuid.uuid4().hex[:8]}", [])
        db.commit()
        membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[empty_role])
        db.add(membership)
        db.commit()
    finally:
        db.close()

    with caplog.at_level(logging.WARNING, logger="omnibioai.auth.permission_parity"):
        resp = client.post("/auth/login", json={"email": email, "password": "TestPassword123!"})
    assert resp.status_code == 200
    assert any("permission_parity_mismatch" in r.message for r in caplog.records)
