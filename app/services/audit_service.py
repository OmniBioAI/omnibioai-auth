"""PR9 (Enterprise IAM Foundation): the single place every persistent IAM
audit event is written from. Called from inside role_service.py/
org_service.py/auth_service.py, at the exact point each mutation actually
happens -- never from a route handler -- so a mutation reachable from
multiple routes (e.g. org_service.set_member_roles, called by both
routes_orgs.py's legacy PUT and routes_organization_roles.py's PR7 POST)
still emits exactly one event, and a route can never accidentally emit
zero or two.

Never raises: a failure writing an audit row must not break the real
mutation it describes, mirroring the "NEVER break core system" principle
the sibling omnibioai-security-audit service's own AuditLogger.log()
already applies to its Redis writes. This audit write is a *separate*
commit from the mutation's own (which has already succeeded by the time
log_event runs) -- not atomic with it. A crash in the narrow window
between the two would lose the audit row but keep the real mutation; the
alternative (folding the audit insert into each mutation's existing
transaction) would mean editing the commit boundary of every one of those
functions, a materially larger and riskier change for this PR. Documented
here as a known, deliberate tradeoff, not an oversight.
"""
import logging

from sqlalchemy.orm import Session

from app.db.models import AuditEvent

logger = logging.getLogger("omnibioai.auth.audit")


class AuditEventType:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ROLE_CREATED = "role_created"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    ORG_MEMBERSHIP_CHANGED = "organization_membership_changed"


def log_event(
    db: Session,
    event_type: str,
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
    organization_id: int | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    before_state: dict | None = None,
    after_state: dict | None = None,
    metadata: dict | None = None,
) -> None:
    try:
        event = AuditEvent(
            event_type=event_type,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            before_state=before_state,
            after_state=after_state,
            event_metadata=metadata,
        )
        db.add(event)
        db.commit()
    except Exception:
        logger.exception("audit_event_write_failed event_type=%s", event_type)
        db.rollback()
