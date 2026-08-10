from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, Team, TeamMember, User

# Team Management v0.8.0 Step 2. Deliberately a plain, app-checked set of
# strings -- not routed through the org-level Role/Permission machinery
# `membership_roles` already uses (see 0020_team_member_roles.py's
# docstring). Checked directly in route handlers/here, not via a
# require_permission-style dependency.
TEAM_ROLES = {"admin", "member", "viewer"}
DEFAULT_TEAM_ROLE = "member"


def create_team(
    db: Session, organization_id: int, name: str, description: str | None = None,
    created_by: User | None = None,
) -> Team:
    team = Team(
        organization_id=organization_id, name=name, description=description,
        created_by_user_id=created_by.id if created_by else None,
        created_at=datetime.utcnow(),
    )
    db.add(team)
    db.commit()
    db.refresh(team)
    return team


def update_team(
    db: Session, team: Team, *, name: str | None = None, description: str | None = None,
) -> Team:
    """PATCH semantics: a field only changes if the caller actually passed
    it (None means "leave alone", not "clear this field") -- same
    convention org_service.update_organization already follows."""
    if name is not None:
        team.name = name
    if description is not None:
        team.description = description
    db.commit()
    db.refresh(team)
    return team


def list_teams(db: Session, organization_id: int) -> list[Team]:
    return db.query(Team).filter(Team.organization_id == organization_id).all()


def get_team(db: Session, organization_id: int, team_id: int) -> Team | None:
    return (
        db.query(Team)
        .filter(Team.id == team_id, Team.organization_id == organization_id)
        .first()
    )


def delete_team(db: Session, team: Team) -> None:
    db.delete(team)
    db.commit()


def set_team_members(db: Session, team: Team, organization_id: int, user_ids: list[int]) -> Team:
    """Restricts membership to users who already belong to the team's own
    organization -- without this check, a raw user_id in the request body
    could add a member from a completely different org into this team."""
    valid_user_ids = {
        m.user_id
        for m in db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id.in_(user_ids),
        )
        .all()
    }
    invalid = set(user_ids) - valid_user_ids
    if invalid:
        raise ValueError(f"Users not members of this organization: {sorted(invalid)}")

    team.members = db.query(User).filter(User.id.in_(valid_user_ids)).all()
    db.commit()
    db.refresh(team)
    return team


# ---------------------------------------------------------------------------
# Per-member operations (Team Management v0.8.0 Step 2). Read/write
# TeamMember directly (the app/db/models.py association-object mapped onto
# team_memberships) rather than going through Team.members' `secondary=`
# collection above -- that collection has no access to role/invited_by/
# joined_at. set_team_members's bulk full-replace path is untouched and
# keeps working exactly as before, alongside these.
# ---------------------------------------------------------------------------


def list_team_members(db: Session, team_id: int) -> list[TeamMember]:
    return (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id)
        .order_by(TeamMember.role, TeamMember.user_id)
        .all()
    )


def get_team_member(db: Session, team_id: int, user_id: int) -> TeamMember | None:
    return (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id, TeamMember.user_id == user_id)
        .first()
    )


def _admin_count(db: Session, team_id: int) -> int:
    return (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team_id, TeamMember.role == "admin")
        .count()
    )


def _is_last_admin(db: Session, member: TeamMember) -> bool:
    """True if `member` is currently an admin and removing/demoting them
    would leave the team with zero admins. The "owner = distinguished
    admin" model this feature uses (decision: no separate owner_user_id
    field) depends on every team always keeping at least one -- this is
    the single choke point remove_member/leave_team/set_member_role below
    all go through to enforce that."""
    return member.role == "admin" and _admin_count(db, member.team_id) <= 1


def invite_to_team(
    db: Session, team: Team, organization_id: int, email: str, invited_by: User,
    role: str = DEFAULT_TEAM_ROLE,
) -> TeamMember | None:
    """Mirrors org_service.invite_member's shape exactly: returns None if
    no account exists for that email yet (caller translates to 404) --
    inviting an unregistered address isn't supported here either.

    Unlike org-level invite, the invitee must *already* be a member of
    this team's organization -- teams are internal/org-owned per v0.8.0
    scope (cross-org teams are deferred to v0.9.0). An org outsider
    raises ValueError (caller translates to 400), the same guard
    set_team_members already enforces for its own bulk-replace path.

    Idempotent like org_service.invite_member: inviting someone already
    on the team returns their existing membership unchanged (role is not
    silently overwritten by a re-invite -- use set_member_role for that).
    """
    if role not in TEAM_ROLES:
        raise ValueError(f"Invalid role: {role!r} (expected one of {sorted(TEAM_ROLES)})")

    invitee = db.query(User).filter(User.email == email).first()
    if not invitee:
        return None

    is_org_member = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == invitee.id,
        )
        .first()
        is not None
    )
    if not is_org_member:
        raise ValueError(f"User is not a member of this organization: {email}")

    existing = get_team_member(db, team.id, invitee.id)
    if existing:
        return existing

    member = TeamMember(
        team_id=team.id, user_id=invitee.id, role=role,
        invited_by_user_id=invited_by.id, joined_at=datetime.utcnow(),
    )
    db.add(member)
    db.commit()
    db.refresh(member)
    return member


def set_member_role(db: Session, member: TeamMember, new_role: str) -> TeamMember:
    """Raises ValueError for an unrecognized role name, or for demoting
    the team's last remaining admin -- see _is_last_admin."""
    if new_role not in TEAM_ROLES:
        raise ValueError(f"Invalid role: {new_role!r} (expected one of {sorted(TEAM_ROLES)})")
    if new_role != "admin" and _is_last_admin(db, member):
        raise ValueError("Cannot demote the last team admin")
    member.role = new_role
    db.commit()
    db.refresh(member)
    return member


def remove_member(db: Session, member: TeamMember) -> None:
    """Raises ValueError if removing this member would leave the team
    with zero admins."""
    if _is_last_admin(db, member):
        raise ValueError("Cannot remove the last team admin")
    db.delete(member)
    db.commit()


def leave_team(db: Session, member: TeamMember) -> None:
    """Self-service counterpart to remove_member, for a member removing
    themselves. Same last-admin guard (decision: last admin cannot leave),
    distinct error message since the actor and the target are the same
    person here."""
    if _is_last_admin(db, member):
        raise ValueError(
            "The last team admin cannot leave -- transfer ownership or delete the team instead"
        )
    db.delete(member)
    db.commit()
