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


class SwitchTeamRequest(BaseModel):
    # `team_id` is required (unlike RefreshRequest.refresh_token's
    # optional-with-cookie-fallback shape above) precisely so it can be
    # sent as an explicit `null` for "switch back to the personal
    # workspace" -- omitting the field entirely would be ambiguous with
    # "no opinion, leave my current workspace alone", which is what plain
    # POST /auth/refresh already means (see auth_service.rotate_refresh_
    # token's `_UNSET` sentinel). This endpoint has no such "no opinion"
    # case; every call is an explicit switch.
    team_id: int | None
    # Same cookie-fallback convention as RefreshRequest.refresh_token.
    refresh_token: str | None = None