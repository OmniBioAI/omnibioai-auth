from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, Team
from app.db.session import get_db
from app.rbac import get_org_membership, require_org_permission
from app.schemas.teams import TeamCreate, TeamMembersUpdate, TeamOut
from app.services import team_service

router = APIRouter(prefix="/orgs/{org_id}/teams", tags=["teams"])

MANAGE_TEAMS = "manage_teams"


def _team_out(team: Team) -> TeamOut:
    return TeamOut(
        id=team.id,
        organization_id=team.organization_id,
        name=team.name,
        member_user_ids=sorted(u.id for u in team.members),
    )


@router.post("", response_model=TeamOut, status_code=201)
def create_team(
    org_id: int,
    body: TeamCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_TEAMS)),
):
    team = team_service.create_team(db, org_id, body.name)
    return _team_out(team)


@router.get("", response_model=list[TeamOut])
def list_teams(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(get_org_membership),
):
    return [_team_out(t) for t in team_service.list_teams(db, org_id)]


@router.put("/{team_id}/members", response_model=TeamOut)
def set_team_members(
    org_id: int,
    team_id: int,
    body: TeamMembersUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_TEAMS)),
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
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_TEAMS)),
):
    team = team_service.get_team(db, org_id, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    team_service.delete_team(db, team)
