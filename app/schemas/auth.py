from pydantic import BaseModel

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    # SSO Phase 2 PR10: optional so a browser session relying solely on the
    # omnibioai_session cookie (no body at all, or an empty body) can still
    # refresh -- routes_auth.py's refresh() falls back to the cookie when
    # this is absent. A body-supplied token still always wins when present
    # (existing API clients that only ever used the body are unaffected).
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str
    access_token: str | None = None