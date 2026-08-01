"""Phase 1 PR3: scripts/backfill_default_org.py correctness --
transactional, idempotent, never touches user_roles, has a real
verify-only mode.
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Organization, OrganizationMembership, User
from app.services import role_service
from scripts.backfill_default_org import backfill

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db(client):
    # `client` fixture (unused directly) guarantees app.main has already
    # run -- which is what actually creates the Default Organization this
    # backfill script requires to exist (app/db/init_admin.py's
    # ensure_default_organization(), called at app import time).
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


def _make_user_with_role(db, permission_names):
    role = role_service.get_or_create_role(db, f"backfill-role-{uuid.uuid4().hex[:8]}", permission_names)
    db.commit()
    user = User(
        email=f"backfill-{uuid.uuid4().hex[:8]}@omnibioai.test",
        hashed_password=None,
        status="active",
        roles=[role],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _default_org(db):
    return db.query(Organization).filter(Organization.slug == "default").first()


# ── Correctness ──────────────────────────────────────────────────────────────


def test_backfill_creates_membership_matching_global_permissions(db):
    user = _make_user_with_role(db, ["read:samples", "write:samples"])
    original_role_ids = sorted(r.id for r in user.roles)

    result = backfill(db, verify_only=False)
    assert result["mismatches"] == []

    org = _default_org(db)
    membership = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org.id, OrganizationMembership.user_id == user.id)
        .first()
    )
    assert membership is not None
    assert membership.status == "active"
    assert sorted(r.name for r in membership.roles) == sorted(r.name for r in user.roles)

    # Never modifies the original user_roles rows: same Role ids, still there.
    db.refresh(user)
    assert sorted(r.id for r in user.roles) == original_role_ids


def test_backfill_never_touches_global_config(db):
    """Doesn't assert much beyond "the table isn't gone" -- the real
    guarantee is structural (the script's source never imports or
    queries GlobalConfig at all), verified separately by code review, but
    this at least catches an accidental future regression that starts
    touching it."""
    from app.db.models import GlobalConfig

    before = db.query(GlobalConfig).count()
    backfill(db, verify_only=False)
    after = db.query(GlobalConfig).count()
    assert before == after


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_backfill_is_idempotent(db):
    user = _make_user_with_role(db, ["read:samples"])

    first = backfill(db, verify_only=False)
    assert first["backfilled"] >= 1

    org = _default_org(db)
    count_after_first = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org.id, OrganizationMembership.user_id == user.id)
        .count()
    )
    assert count_after_first == 1

    second = backfill(db, verify_only=False)
    assert second["mismatches"] == []

    count_after_second = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org.id, OrganizationMembership.user_id == user.id)
        .count()
    )
    assert count_after_second == 1  # no duplicate row


def test_backfill_detects_diverged_existing_membership(db):
    """If a membership already exists (e.g. from a previous partial run or
    manual intervention) but its permissions no longer match the user's
    current global roles, that must be reported as a mismatch -- not
    silently left alone and not silently overwritten."""
    user = _make_user_with_role(db, ["read:samples"])
    backfill(db, verify_only=False)  # first pass creates the matching membership

    # Now change the user's global role assignment without touching the
    # already-backfilled org membership -- simulates drift.
    new_role = role_service.get_or_create_role(db, f"backfill-drift-{uuid.uuid4().hex[:8]}", ["write:samples"])
    db.commit()
    user.roles = [new_role]
    db.commit()

    result = backfill(db, verify_only=False)
    assert len(result["mismatches"]) == 1
    assert result["mismatches"][0]["user_id"] == user.id


# ── Verify-only mode ─────────────────────────────────────────────────────────


def test_verify_mode_writes_nothing(db):
    user = _make_user_with_role(db, ["read:samples"])
    org = _default_org(db)

    before = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org.id, OrganizationMembership.user_id == user.id)
        .count()
    )
    assert before == 0

    result = backfill(db, verify_only=True)
    assert result["backfilled"] >= 1  # would-be count reported

    after = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == org.id, OrganizationMembership.user_id == user.id)
        .count()
    )
    assert after == 0  # but nothing was actually written


# ── Missing Default Organization ────────────────────────────────────────────


def test_raises_without_default_organization(tmp_path):
    """Isolated throwaway DB, deliberately never running
    ensure_default_organization -- confirms the script fails loudly rather
    than silently backfilling into a nonexistent org."""
    import app.db.models  # noqa: F401 -- registers all tables on Base.metadata

    db_file = tmp_path / "no_default_org.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        with pytest.raises(RuntimeError, match="No Default Organization found"):
            backfill(session, verify_only=True)
    finally:
        session.close()
