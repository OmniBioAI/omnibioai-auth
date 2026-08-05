"""PR11.4b (Identity Audit Trail Foundation): response shape for the
read-only GET /platform/audit-events endpoint. Mirrors
schemas/user_admin.py's PlatformUserListOut pagination shape exactly
(items/total/page/page_size/total_pages), the same convention every
other /platform/* list endpoint in this codebase already uses.
"""
from datetime import datetime

from pydantic import BaseModel


class AuditEventOut(BaseModel):
    id: int
    event_type: str
    actor_user_id: int | None
    # Best-effort display resolution (app/services/audit_service.py::
    # resolve_display_fields) -- None if the referenced user/org no
    # longer exists, never fabricated. See AuditEvent's own model
    # docstring for why actor_user_id itself is kept even then.
    actor_email: str | None
    target_user_id: int | None
    target_email: str | None
    organization_id: int | None
    organization_name: str | None
    resource_type: str | None
    resource_id: str | None
    before_state: dict | None
    after_state: dict | None
    # Never client_secret/api_key/tokens -- every log_event call site
    # that writes this field is responsible for that, not this schema;
    # see docs/pr11-identity-audit-discovery.md and each call site's own
    # comment for the specific exclusions.
    metadata: dict | None
    created_at: datetime | None


class AuditEventListOut(BaseModel):
    items: list[AuditEventOut]
    total: int
    page: int
    page_size: int
    total_pages: int
