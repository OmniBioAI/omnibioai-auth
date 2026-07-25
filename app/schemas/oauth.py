from pydantic import BaseModel


class OAuthCallbackBody(BaseModel):
    code: str
    state: str


class OAuthLinkConfirmRequest(BaseModel):
    link_token: str
    password: str
