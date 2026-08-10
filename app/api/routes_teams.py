from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, Team, User
from app.db.session import get_db
from app.rbac import get_current_user, get_org_membership_or_platform_admin, require_org_permission_or_platform_admin
from app.schemas.teams import (
    TeamCreate, TeamInvite, TeamMemberOut, TeamMemberRoleUpdate, TeamMembersUpdate, TeamOut, TeamUpdate,
)
from app.services import team_service

router = APIRouter(prefix="/orgs/{org_id}/teams", tags=["teams"])

MANAGE_TEAMS = "manage_teams"


def _team_out(team: Team) -> TeamOut:
    return TeamOut(
        id=team.id,
        organization_id=team.organization_id,
        name=team.name,
        description=team.description,
        created_by_user_id=team.created_by_user_id,
        member_user_ids=sorted(u.id for u in team.members),
    )


def _team_member_out(member) -> TeamMemberOut:
    return TeamMemberOut(
        user_id=member.user_id,
        role=member.role,
        invited_by_user_id=member.invited_by_user_id,
        joined_at=member.joined_at,
    )


def _has_manage_teams(membership: OrganizationMembership) -> bool:
    return MANAGE_TEAMS in {p.name for role in membership.roles for p in role.permissions}


# ---------------------------------------------------------------------------
# Step 3: permission checks are written directly in each route handler
# below -- decision was to check role directly in route handlers rather
# than build a require_permission-style dependency for it. _has_manage_teams
# above is a tiny, non-authorizing lookup helper (reads a set of names off
# an already-resolved membership), not the "team-role permission helper"
# Step 4 adds -- it's what Step 4 will use to replace the repeated
# if not _has_manage_teams(...): <team-admin fallback>: raise 403 shape
# every mutating per-member handler below carries. Decision: org
# manage_teams always overrides team roles (an org admin manages every
# team in the org regardless of their own team-level role, or lack of
# one); a team admin manages only members + rename on their own team.
# ---------------------------------------------------------------------------


@router.post("", response_model=TeamOut, status_code=201)
def create_team(
    org_id: int,
    body: TeamCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_TEAMS)),
):
    creator = db.query(User).filter(User.id == int(user["sub"])).first()
    team = team_service.create_team(db, org_id, body.name, description=body.description, created_by=creator)
    return _team_out(team)


@router.get("", response_model=list[TeamOut])
def list_teams(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    return [_team_out(t) for t in team_service.list_teams(db, org_id)]


@router.get("/{team_id}", response_model=TeamOut)
def get_team_detail(
    org_id: int,
    team_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    return _team_out(team)


@router.patch("/{team_id}", response_model=TeamOut)
def rename_team(
    org_id: int,
    team_id: int,
    body: TeamUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    if not _has_manage_teams(membership):
        caller_member = team_service.get_team_member(db, team_id, int(user["sub"]))
        if not caller_member or caller_member.role != "admin":
            raise HTTPException(403, "Forbidden")

    team = team_service.update_team(db, team, name=body.name, description=body.description)
    return _team_out(team)


@router.get("/{team_id}/members", response_model=list[TeamMemberOut])
def get_team_members(
    org_id: int,
    team_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    return [_team_member_out(m) for m in team_service.list_team_members(db, team_id)]


@router.post("/{team_id}/invite", response_model=TeamMemberOut, status_code=201)
def invite_team_member(
    org_id: int,
    team_id: int,
    body: TeamInvite,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    if not _has_manage_teams(membership):
        caller_member = team_service.get_team_member(db, team_id, int(user["sub"]))
        if not caller_member or caller_member.role != "admin":
            raise HTTPException(403, "Forbidden")

    inviter = db.query(User).filter(User.id == int(user["sub"])).first()
    try:
        member = team_service.invite_to_team(db, team, org_id, body.email, inviter, role=body.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if member is None:
        raise HTTPException(404, "No account exists for that email yet")
    return _team_member_out(member)


@router.put("/{team_id}/members/{user_id}/role", response_model=TeamMemberOut)
def update_team_member_role(
    org_id: int,
    team_id: int,
    user_id: int,
    body: TeamMemberRoleUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    if not _has_manage_teams(membership):
        caller_member = team_service.get_team_member(db, team_id, int(user["sub"]))
        if not caller_member or caller_member.role != "admin":
            raise HTTPException(403, "Forbidden")

    target = team_service.get_team_member(db, team_id, user_id)
    if not target:
        raise HTTPException(404, "Team member not found")

    try:
        updated = team_service.set_member_role(db, target, body.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _team_member_out(updated)


@router.delete("/{team_id}/members/{user_id}", status_code=204)
def remove_team_member(
    org_id: int,
    team_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    if not _has_manage_teams(membership):
        caller_member = team_service.get_team_member(db, team_id, int(user["sub"]))
        if not caller_member or caller_member.role != "admin":
            raise HTTPException(403, "Forbidden")

    target = team_service.get_team_member(db, team_id, user_id)
    if not target:
        raise HTTPException(404, "Team member not found")

    try:
        team_service.remove_member(db, target)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{team_id}/leave", status_code=204)
def leave_team(
    org_id: int,
    team_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    """Self-service -- deliberately no manage_teams/team-admin gate: any
    member (of any role) may leave their own team. The last-admin guard
    (decision: last admin cannot leave) is enforced by
    team_service.leave_team, not here."""
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    member = team_service.get_team_member(db, team_id, int(user["sub"]))
    if not member:
        raise HTTPException(404, "Not a member of this team")

    try:
        team_service.leave_team(db, member)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{team_id}/members", response_model=TeamOut)
def set_team_members(
    org_id: int,
    team_id: int,
    body: TeamMembersUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_TEAMS)),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    try:
        team = team_service.set_team_members(db, team, org_id, body.user_ids)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _team_out(team)


@router.delete("/{team_id}", status_code=204)
def delete_team(
    org_id: int,
    team_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_TEAMS)),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    team_service.delete_team(db, team)
