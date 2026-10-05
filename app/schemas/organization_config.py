"""
OmniBioAI app.schemas.organization_config.

Purpose:
    Defines ProviderKeyIn, ProviderKeyOut and ProviderKeyRevealOut for app.schemas.organization_config.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from pydantic import BaseModel


class ProviderKeyIn(BaseModel):
    api_key: str


class ProviderKeyOut(BaseModel):
    """No credential field, ever, regardless of caller role -- has_key
    only, the same write-only convention app/schemas/config.py's
    GlobalConfigOut already established for the platform-wide LLM key."""
    provider: str | None
    has_key: bool
    updated_at: str | None
    updated_by_email: str | None


class ProviderKeyRevealOut(BaseModel):
    """M16: the one response shape in this module that DOES carry the
    real key -- POST /internal/.../reveal is service-to-service only
    (shared-secret gated, see routes_organization_config.py), never
    reachable by a user or API-key token."""
    provider: str
    api_key: str
