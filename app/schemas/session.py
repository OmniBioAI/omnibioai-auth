"""Phase 4 PR-A (Session Foundation): response shape for GET /sessions,
GET /sessions/{session_id}, and POST /sessions/{session_id}/revoke.

Self-service only in this PR -- every field here is something the
session's own owner is already entitled to see about their own login.
Deliberately excludes `user_id` (always the caller, in a self-service
endpoint) and anything token/secret-shaped -- see
app/api/routes_sessions.py's module docstring and app/db/models.py::
UserSession's own docstring for why no such field exists on this table
to begin with.
"""
from datetime import datetime

from pydantic import BaseModel


class SessionOut(BaseModel):
    session_id: str
    organization_id: int | None = None
    auth_method: str | None = None
    mfa_verified: bool
    status: str
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None
