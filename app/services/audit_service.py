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
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import AuditEvent, Organization, User

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
    # PR11.4b (Identity Audit Trail Foundation). See
    # docs/pr11-identity-audit-discovery.md (omnibioai-control-center)
    # for the full discovery this set was built from.
    USER_ENABLED = "user_enabled"
    USER_DISABLED = "user_disabled"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    OAUTH_CLIENT_CREATED = "oauth_client_created"
    OAUTH_CLIENT_REVOKED = "oauth_client_revoked"
    SSO_CONFIGURATION_CREATED = "sso_configuration_created"
    SSO_CONFIGURATION_UPDATED = "sso_configuration_updated"
    SSO_ENFORCEMENT_CHANGED = "sso_enforcement_changed"
    # PR11.4c (Break-Glass Audit Completion). See
    # docs/pr11-breakglass-audit-discovery.md (omnibioai-control-center).
    SSO_OVERRIDE_CREATED = "sso_override_created"
    SSO_OVERRIDE_REMOVED = "sso_override_removed"
    # PR11.5.2 (Enterprise TOTP MFA Enrollment). See
    # docs/pr11-totp-enrollment-discovery.md. MFA_RESET_BY_ADMIN and
    # MFA_RECOVERY_USED (named in PR11.5.1's own roadmap) are deliberately
    # not added yet -- this PR implements neither admin reset nor recovery
    # codes, so those constants would have nothing to emit them until the
    # PR that actually adds that functionality (PR11.5.4).
    MFA_DEVICE_ENROLLMENT_STARTED = "mfa_device_enrollment_started"
    MFA_DEVICE_ADDED = "mfa_device_added"
    MFA_DEVICE_REMOVED = "mfa_device_removed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"


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


# ---------------------------------------------------------------------------
# PR11.4b (Identity Audit Trail Foundation): read side. No retrieval API
# existed before this PR (confirmed by discovery -- see
# docs/pr11-identity-audit-discovery.md in omnibioai-control-center) --
# added here, in the same module as log_event, rather than a new
# platform_audit_service.py, since this module is already the single
# source of truth for the AuditEvent table on the write side.
# ---------------------------------------------------------------------------


def list_events(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    organization_id: int | None = None,
    actor_user_id: int | None = None,
    event_type: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[AuditEvent], int]:
    """Returns (page of events, total matching) -- same
    (items, total)-tuple contract user_admin_service.list_users already
    uses, so routes_platform_audit.py's pagination math mirrors
    routes_platform_users.py's exactly. All filters optional and
    AND-combined; an omitted filter matches everything, same convention
    list_users's own filters already follow. Newest first -- created_at
    DESC, id DESC as a tiebreaker for events written in the same
    microsecond (SQLite/some backends' datetime resolution isn't always
    fine enough to order same-transaction rows by created_at alone).
    """
    query = db.query(AuditEvent)
    if organization_id is not None:
        query = query.filter(AuditEvent.organization_id == organization_id)
    if actor_user_id is not None:
        query = query.filter(AuditEvent.actor_user_id == actor_user_id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if start_date is not None:
        query = query.filter(AuditEvent.created_at >= start_date)
    if end_date is not None:
        query = query.filter(AuditEvent.created_at <= end_date)

    total = query.count()
    events = (
        query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return events, total


def resolve_display_fields(db: Session, events: list[AuditEvent]) -> dict[int, dict]:
    """Batched actor_email/target_email/organization_name lookup for a
    page of events -- {event.id: {...}}. Mirrors the existing
    user_admin_service._org_counts_by_user / platform_admin_service.
    _counts_by_org batching pattern (one IN-clause query per id-set for
    the whole page, never one query per row) -- AuditEvent itself has no
    denormalized email/name columns and deliberately no FK relationship
    to User/Organization (see AuditEvent's own docstring: a row must
    outlive the record it references), so this is the only way to
    display them without an N+1.
    """
    user_ids: set[int] = set()
    org_ids: set[int] = set()
    for e in events:
        if e.actor_user_id is not None:
            user_ids.add(e.actor_user_id)
        if e.target_user_id is not None:
            user_ids.add(e.target_user_id)
        if e.organization_id is not None:
            org_ids.add(e.organization_id)

    emails_by_id: dict[int, str] = {}
    if user_ids:
        rows = db.query(User.id, User.email).filter(User.id.in_(user_ids)).all()
        emails_by_id = dict(rows)

    org_names_by_id: dict[int, str] = {}
    if org_ids:
        rows = db.query(Organization.id, Organization.name).filter(Organization.id.in_(org_ids)).all()
        org_names_by_id = dict(rows)

    return {
        e.id: {
            "actor_email": emails_by_id.get(e.actor_user_id) if e.actor_user_id is not None else None,
            "target_email": emails_by_id.get(e.target_user_id) if e.target_user_id is not None else None,
            "organization_name": org_names_by_id.get(e.organization_id) if e.organization_id is not None else None,
        }
        for e in events
    }
