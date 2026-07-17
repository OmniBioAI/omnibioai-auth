from pydantic import BaseModel


class RoleCreate(BaseModel):
    name: str
    permissions: list[str] = []


class RoleUpdate(BaseModel):
    permissions: list[str]


class RoleOut(BaseModel):
    id: int
    name: str
    permission_count: int
    user_count: int


class RoleDetailOut(BaseModel):
    id: int
    name: str
    permissions: list[str]


class UserRolesOut(BaseModel):
    user_id: int
    roles: list[str]


class UserRolesUpdate(BaseModel):
    roles: list[str]
