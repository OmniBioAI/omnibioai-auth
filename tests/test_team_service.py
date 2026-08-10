"""Team Management v0.8.0 Step 2: app/services/team_service.py's new
per-member operations (invite/set_member_role/remove_member/leave_team)
plus the extended create_team/update_team.

Exercised directly against a throwaway in-memory SQLite session -- no
HTTP client, no authorization layer (that's Step 3/4's concern) -- these
tests are only about the service layer's own business rules: org
membership gating on invite, and the "every team keeps at least one
admin" invariant (decision: owner = distinguished admin role member, no
separate owner_user_id field, so this invariant is the only thing
standing in for ownership transfer/deletion being the only ways out).
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Organization, OrganizationMembership, User
from app.services import team_service


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _org(db, slug="org"):
    org = Organization(slug=slug, name=slug)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def _user(db, email):
    user = User(email=email, hashed_password="not-a-real-hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _join_org(db, org, user):
    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active")
    db.add(membership)
    db.commit()
    return membership


# ── create_team / update_team ────────────────────────────────────────────


def test_create_team_sets_description_and_created_by(db):
    org = _org(db)
    creator = _user(db, "creator@omnibioai.test")

    team = team_service.create_team(db, org.id, "Wet Lab", description="Bench work", created_by=creator)

    assert team.name == "Wet Lab"
    assert team.description == "Bench work"
    assert team.created_by_user_id == creator.id


def test_create_team_without_description_or_creator_still_works(db):
    """Existing callers (routes_teams.py's create_team, pre-Step-3) only
    ever pass name -- both new params must stay optional."""
    org = _org(db)
    team = team_service.create_team(db, org.id, "No Frills")
    assert team.description is None
    assert team.created_by_user_id is None


def test_update_team_rename_only_leaves_description_unchanged(db):
    org = _org(db)
    team = team_service.create_team(db, org.id, "Old Name", description="Keep me")

    updated = team_service.update_team(db, team, name="New Name")

    assert updated.name == "New Name"
    assert updated.description == "Keep me"


def test_update_team_description_only_leaves_name_unchanged(db):
    org = _org(db)
    team = team_service.create_team(db, org.id, "Stays The Same")

    updated = team_service.update_team(db, team, description="Now has a description")

    assert updated.name == "Stays The Same"
    assert updated.description == "Now has a description"


# ── invite_to_team ────────────────────────────────────────────────────────


def test_invite_to_team_returns_none_for_unknown_email(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    team = team_service.create_team(db, org.id, "Team")

    result = team_service.invite_to_team(db, team, org.id, "nobody@omnibioai.test", inviter)

    assert result is None


def test_invite_to_team_rejects_non_org_member(db):
    """The invitee has an account but never joined this team's
    organization -- teams are internal/org-owned per v0.8.0 scope."""
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    outsider = _user(db, "outsider@omnibioai.test")
    team = team_service.create_team(db, org.id, "Team")

    with pytest.raises(ValueError, match="not a member of this organization"):
        team_service.invite_to_team(db, team, org.id, outsider.email, inviter)


def test_invite_to_team_rejects_invalid_role(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    invitee = _user(db, "invitee@omnibioai.test")
    _join_org(db, org, invitee)
    team = team_service.create_team(db, org.id, "Team")

    with pytest.raises(ValueError, match="Invalid role"):
        team_service.invite_to_team(db, team, org.id, invitee.email, inviter, role="owner")


def test_invite_to_team_creates_member_with_role_and_invited_by(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    invitee = _user(db, "invitee@omnibioai.test")
    _join_org(db, org, invitee)
    team = team_service.create_team(db, org.id, "Team")

    member = team_service.invite_to_team(db, team, org.id, invitee.email, inviter, role="viewer")

    assert member is not None
    assert member.team_id == team.id
    assert member.user_id == invitee.id
    assert member.role == "viewer"
    assert member.invited_by_user_id == inviter.id
    assert member.joined_at is not None


def test_invite_to_team_defaults_to_member_role(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    invitee = _user(db, "invitee@omnibioai.test")
    _join_org(db, org, invitee)
    team = team_service.create_team(db, org.id, "Team")

    member = team_service.invite_to_team(db, team, org.id, invitee.email, inviter)

    assert member.role == "member"


def test_invite_to_team_is_idempotent_and_does_not_change_role(db):
    """Re-inviting someone already on the team returns their existing
    membership unchanged -- a re-invite is not a silent role change (use
    set_member_role for that), mirroring org_service.invite_member's own
    idempotency."""
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    invitee = _user(db, "invitee@omnibioai.test")
    _join_org(db, org, invitee)
    team = team_service.create_team(db, org.id, "Team")

    first = team_service.invite_to_team(db, team, org.id, invitee.email, inviter, role="admin")
    second = team_service.invite_to_team(db, team, org.id, invitee.email, inviter, role="viewer")

    assert second.role == "admin"
    assert first.user_id == second.user_id


# ── set_member_role ───────────────────────────────────────────────────────


def test_set_member_role_updates_role(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    member_user = _user(db, "member@omnibioai.test")
    _join_org(db, org, member_user)
    team = team_service.create_team(db, org.id, "Team")
    member = team_service.invite_to_team(db, team, org.id, member_user.email, inviter, role="viewer")

    updated = team_service.set_member_role(db, member, "admin")

    assert updated.role == "admin"


def test_set_member_role_rejects_invalid_role(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    member_user = _user(db, "member@omnibioai.test")
    _join_org(db, org, member_user)
    team = team_service.create_team(db, org.id, "Team")
    member = team_service.invite_to_team(db, team, org.id, member_user.email, inviter)

    with pytest.raises(ValueError, match="Invalid role"):
        team_service.set_member_role(db, member, "owner")


def test_set_member_role_blocks_demoting_the_last_admin(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    admin_user = _user(db, "admin@omnibioai.test")
    _join_org(db, org, admin_user)
    team = team_service.create_team(db, org.id, "Team")
    admin_member = team_service.invite_to_team(db, team, org.id, admin_user.email, inviter, role="admin")

    with pytest.raises(ValueError, match="last team admin"):
        team_service.set_member_role(db, admin_member, "member")

    assert admin_member.role == "admin"


def test_set_member_role_allows_demoting_admin_when_another_admin_exists(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    admin1 = _user(db, "admin1@omnibioai.test")
    admin2 = _user(db, "admin2@omnibioai.test")
    _join_org(db, org, admin1)
    _join_org(db, org, admin2)
    team = team_service.create_team(db, org.id, "Team")
    member1 = team_service.invite_to_team(db, team, org.id, admin1.email, inviter, role="admin")
    team_service.invite_to_team(db, team, org.id, admin2.email, inviter, role="admin")

    updated = team_service.set_member_role(db, member1, "member")

    assert updated.role == "member"


# ── remove_member / leave_team ───────────────────────────────────────────


def test_remove_member_blocks_removing_the_last_admin(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    admin_user = _user(db, "admin@omnibioai.test")
    _join_org(db, org, admin_user)
    team = team_service.create_team(db, org.id, "Team")
    admin_member = team_service.invite_to_team(db, team, org.id, admin_user.email, inviter, role="admin")

    with pytest.raises(ValueError, match="last team admin"):
        team_service.remove_member(db, admin_member)

    assert team_service.get_team_member(db, team.id, admin_user.id) is not None


def test_remove_member_allows_removing_a_non_admin(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    member_user = _user(db, "member@omnibioai.test")
    _join_org(db, org, member_user)
    team = team_service.create_team(db, org.id, "Team")
    member = team_service.invite_to_team(db, team, org.id, member_user.email, inviter, role="member")

    team_service.remove_member(db, member)

    assert team_service.get_team_member(db, team.id, member_user.id) is None


def test_leave_team_blocks_the_last_admin(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    admin_user = _user(db, "admin@omnibioai.test")
    _join_org(db, org, admin_user)
    team = team_service.create_team(db, org.id, "Team")
    admin_member = team_service.invite_to_team(db, team, org.id, admin_user.email, inviter, role="admin")

    with pytest.raises(ValueError, match="last team admin cannot leave"):
        team_service.leave_team(db, admin_member)

    assert team_service.get_team_member(db, team.id, admin_user.id) is not None


def test_leave_team_removes_membership_when_not_the_last_admin(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    admin1 = _user(db, "admin1@omnibioai.test")
    admin2 = _user(db, "admin2@omnibioai.test")
    _join_org(db, org, admin1)
    _join_org(db, org, admin2)
    team = team_service.create_team(db, org.id, "Team")
    member1 = team_service.invite_to_team(db, team, org.id, admin1.email, inviter, role="admin")
    team_service.invite_to_team(db, team, org.id, admin2.email, inviter, role="admin")

    team_service.leave_team(db, member1)

    assert team_service.get_team_member(db, team.id, admin1.id) is None


# ── list_team_members / get_team_member ──────────────────────────────────


def test_list_team_members_returns_all_members(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    u1 = _user(db, "u1@omnibioai.test")
    u2 = _user(db, "u2@omnibioai.test")
    _join_org(db, org, u1)
    _join_org(db, org, u2)
    team = team_service.create_team(db, org.id, "Team")
    team_service.invite_to_team(db, team, org.id, u1.email, inviter, role="admin")
    team_service.invite_to_team(db, team, org.id, u2.email, inviter, role="viewer")

    members = team_service.list_team_members(db, team.id)

    assert {m.user_id for m in members} == {u1.id, u2.id}


def test_get_team_member_returns_none_when_absent(db):
    org = _org(db)
    team = team_service.create_team(db, org.id, "Team")
    stranger = _user(db, "stranger@omnibioai.test")

    assert team_service.get_team_member(db, team.id, stranger.id) is None


# ── resolve_team_claim (Team Management v0.8.0 Step 3: JWT team_id) ─────────


def test_resolve_team_claim_returns_none_none_for_no_requested_team(db):
    org = _org(db)
    user = _user(db, "user@omnibioai.test")

    assert team_service.resolve_team_claim(db, org.id, None, user.id) == (None, None)


def test_resolve_team_claim_returns_none_none_when_org_id_is_none(db):
    """A user with no org membership can't have a team claim either --
    teams are always org-scoped."""
    org = _org(db)
    user = _user(db, "user@omnibioai.test")
    team = team_service.create_team(db, org.id, "Team")

    assert team_service.resolve_team_claim(db, None, team.id, user.id) == (None, None)


def test_resolve_team_claim_returns_id_and_role_for_active_member(db):
    org = _org(db)
    inviter = _user(db, "inviter@omnibioai.test")
    member_user = _user(db, "member@omnibioai.test")
    _join_org(db, org, member_user)
    team = team_service.create_team(db, org.id, "Team")
    team_service.invite_to_team(db, team, org.id, member_user.email, inviter, role="viewer")

    resolved_id, resolved_role = team_service.resolve_team_claim(db, org.id, team.id, member_user.id)

    assert resolved_id == team.id
    assert resolved_role == "viewer"


def test_resolve_team_claim_degrades_silently_for_non_member(db):
    org = _org(db)
    user = _user(db, "user@omnibioai.test")
    team = team_service.create_team(db, org.id, "Team")

    assert team_service.resolve_team_claim(db, org.id, team.id, user.id) == (None, None)


def test_resolve_team_claim_degrades_silently_for_wrong_org(db):
    """The team belongs to a different org than the one the caller's own
    org_id claim already resolved -- must not leak across orgs even if
    the user happens to also be a member of the team by user_id alone."""
    org_a = _org(db, slug="org-a")
    org_b = _org(db, slug="org-b")
    inviter = _user(db, "inviter@omnibioai.test")
    member_user = _user(db, "member@omnibioai.test")
    _join_org(db, org_a, member_user)
    team_in_a = team_service.create_team(db, org_a.id, "Team A")
    team_service.invite_to_team(db, team_in_a, org_a.id, member_user.email, inviter, role="admin")

    # Caller's resolved org_id is org_b, not org_a.
    assert team_service.resolve_team_claim(db, org_b.id, team_in_a.id, member_user.id) == (None, None)


def test_resolve_team_claim_degrades_silently_for_unknown_team(db):
    org = _org(db)
    user = _user(db, "user@omnibioai.test")

    assert team_service.resolve_team_claim(db, org.id, 999999, user.id) == (None, None)
