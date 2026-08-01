from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, Team, User


def create_team(db: Session, organization_id: int, name: str) -> Team:
    team = Team(organization_id=organization_id, name=name, created_at=datetime.utcnow())
    db.add(team)
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
