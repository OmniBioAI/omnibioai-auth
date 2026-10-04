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
