from pydantic import BaseModel


class TeamCreate(BaseModel):
    name: str


class TeamOut(BaseModel):
    id: int
    organization_id: int
    name: str
    member_user_ids: list[int]


class TeamMembersUpdate(BaseModel):
    user_ids: list[int]
