"""Designated Platform Owner/Admin invariants at the IAM service layer."""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.init_admin import create_admin, ensure_platform_admin_role
from app.db.models import AuditEvent, User
from app.services import role_service


@pytest.fixture
def policy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "PolicyTestPassword123!")
    engine = create_engine(f"sqlite:///{tmp_path / 'policy.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    create_admin(db)
    ensure_platform_admin_role(db)
    owner = User(email="owner@policy.test", hashed_password="x", status="active")
    db.add(owner)
    db.flush()
    owner.roles.append(role_service.get_role_by_name(db, "platform_admin"))
    owner.roles.append(role_service.get_role_by_name(db, "admin"))
    db.commit()
    yield db
    db.close()


def _new_user(db, prefix):
    user = User(email=f"{prefix}-{uuid.uuid4().hex[:6]}@policy.test", hashed_password="x", status="active")
    db.add(user)
    db.flush()
    role_service.assign_default_role(db, user)
    db.commit()
    return user


def test_second_owner_and_second_admin_are_denied(policy_db):
    candidate = _new_user(policy_db, "candidate")
    with pytest.raises(role_service.PrivilegedRolePolicyError):
        role_service.add_user_role(
            policy_db, candidate, role_service.get_role_by_name(policy_db, "platform_admin"), actor_user_id=candidate.id
        )
    with pytest.raises(role_service.PrivilegedRolePolicyError):
        role_service.add_user_role(
            policy_db, candidate, role_service.get_role_by_name(policy_db, "admin"), actor_user_id=candidate.id
        )


def test_platform_owner_admin_overlap_is_allowed(policy_db):
    owner = policy_db.query(User).filter(User.email == "owner@policy.test").one()
    roles = list(owner.roles)
    role_service.validate_privileged_role_transition(policy_db, owner, roles, actor_user_id=owner.id)
    assert {role.name for role in roles} >= {"platform_admin", "admin"}
    assert {user.id for user in role_service._active_holders(policy_db, "admin")} == {1, owner.id}


def test_inactive_platform_owner_may_keep_admin_overlap(policy_db):
    owner = policy_db.query(User).filter(User.email == "owner@policy.test").one()
    owner.status = "suspended"
    policy_db.commit()
    role_service.validate_privileged_role_transition(policy_db, owner, list(owner.roles), actor_user_id=owner.id)


def test_designated_admin_cannot_be_promoted_to_platform_owner(policy_db):
    admin = policy_db.query(User).filter(User.id == role_service.DESIGNATED_ADMIN_USER_ID).one()
    with pytest.raises(role_service.PrivilegedRolePolicyError):
        role_service.add_user_role(
            policy_db, admin, role_service.get_role_by_name(policy_db, "platform_admin"), actor_user_id=admin.id
        )


def test_multiple_nonprivileged_accounts_are_allowed(policy_db):
    first = _new_user(policy_db, "developer")
    second = _new_user(policy_db, "developer")
    user_role = role_service.get_role_by_name(policy_db, "user")
    role_service.set_user_roles(policy_db, first, [user_role], actor_user_id=first.id)
    role_service.set_user_roles(policy_db, second, [user_role], actor_user_id=second.id)
    assert first.id != second.id


def test_last_privileged_holder_cannot_be_removed(policy_db):
    owner = policy_db.query(User).filter(User.email == "owner@policy.test").one()
    role = role_service.get_role_by_name(policy_db, "platform_admin")
    with pytest.raises(role_service.PrivilegedRolePolicyError):
        role_service.remove_user_role(policy_db, owner, role, actor_user_id=owner.id)


def test_owner_cannot_drop_required_admin_role(policy_db):
    owner = policy_db.query(User).filter(User.email == "owner@policy.test").one()
    role = role_service.get_role_by_name(policy_db, "admin")
    with pytest.raises(role_service.PrivilegedRolePolicyError):
        role_service.remove_user_role(policy_db, owner, role, actor_user_id=owner.id)


def test_explicit_privileged_replacement_is_atomic_and_audited(policy_db):
    owner = policy_db.query(User).filter(User.email == "owner@policy.test").one()
    replacement = _new_user(policy_db, "replacement")
    role_service.replace_privileged_role(
        policy_db, "platform_admin", owner.id, replacement.id,
        actor_user_id=owner.id, reason="authorized recovery exercise",
    )
    policy_db.refresh(owner)
    policy_db.refresh(replacement)
    assert "platform_admin" not in {r.name for r in owner.roles}
    assert "platform_admin" in {r.name for r in replacement.roles}
    assert "admin" not in {r.name for r in owner.roles}
    assert "admin" in {r.name for r in replacement.roles}
    assert policy_db.query(AuditEvent).filter(
        AuditEvent.event_type == "privileged_role_replaced", AuditEvent.target_user_id == replacement.id
    ).count() == 1
