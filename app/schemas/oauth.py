"""
OmniBioAI app.schemas.oauth.

Purpose:
    Defines OAuthCallbackBody and OAuthLinkConfirmRequest for app.schemas.oauth.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from pydantic import BaseModel


class OAuthCallbackBody(BaseModel):
    code: str
    state: str


class OAuthLinkConfirmRequest(BaseModel):
    link_token: str
    password: str
