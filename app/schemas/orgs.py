from pydantic import BaseModel


class OrganizationCreate(BaseModel):
    name: str
    slug: str


class OrganizationOut(BaseModel):
    id: int
    slug: str
    name: str
    plan: str
    status: str


class OrganizationUpdate(BaseModel):
    name: str | None = None


class InviteRequest(BaseModel):
    email: str


class MemberOut(BaseModel):
    user_id: int
    email: str
    status: str
    roles: list[str]


class MemberRolesUpdate(BaseModel):
    roles: list[str]


class MemberRolesOut(BaseModel):
    user_id: int
    roles: list[str]
