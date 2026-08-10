from datetime import datetime

from pydantic import BaseModel


class TeamCreate(BaseModel):
    name: str
    # Team Management v0.8.0 Step 3. Optional -- a caller that doesn't
    # pass it gets the same behavior as before this field existed
    # (team_service.create_team's own default is None).
    description: str | None = None


class TeamOut(BaseModel):
    id: int
    organization_id: int
    name: str
    member_user_ids: list[int]
    # Team Management v0.8.0 Step 3. Purely additive on the wire -- an
    # older client parsing this response just ignores fields it doesn't
    # know about; nothing existing that reads TeamOut breaks.
    description: str | None = None
    created_by_user_id: int | None = None


class TeamUpdate(BaseModel):
    """PATCH body: a field left unset (None) means "leave alone", not
    "clear this field" -- mirrors team_service.update_team's own
    convention (and org_service.update_organization's before it)."""
    name: str | None = None
    description: str | None = None


class TeamMembersUpdate(BaseModel):
    user_ids: list[int]


class TeamMemberOut(BaseModel):
    """One row of GET .../teams/{id}/members -- unlike TeamOut's flat
    member_user_ids list (kept as-is for the pre-existing full-replace
    flow), this carries the per-member role/invite/join data Step 1's
    migration added."""
    user_id: int
    role: str
    invited_by_user_id: int | None
    joined_at: datetime | None


class TeamInvite(BaseModel):
    email: str
    role: str = "member"


class TeamMemberRoleUpdate(BaseModel):
    role: str
