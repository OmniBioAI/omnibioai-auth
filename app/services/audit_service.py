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
    # PR8 (SAML Organization Configuration CRUD). Own event types, not a
    # reuse of SSO_CONFIGURATION_CREATED/UPDATED -- OrganizationSAMLConfig
    # is a genuinely separate table/resource_type ("organization_saml_
    # config"), same reasoning PR6 gave for a parallel OAuthAccount
    # uniqueness constraint rather than widening the OIDC one. No
    # SAML_CONFIGURATION_DELETED: delete_sso_config (OIDC's own precedent)
    # doesn't log an audit event either, so this mirrors that as-is rather
    # than introducing asymmetric coverage between the two protocols.
    SAML_CONFIGURATION_CREATED = "saml_configuration_created"
    SAML_CONFIGURATION_UPDATED = "saml_configuration_updated"
    # #263 (per-org SAML enforcement). Own event type, not a reuse of
    # SSO_ENFORCEMENT_CHANGED -- same "genuinely separate table/resource"
    # reasoning SAML_CONFIGURATION_CREATED/UPDATED already established
    # above, applied to enforcement changes too.
    SAML_ENFORCEMENT_CHANGED = "saml_enforcement_changed"
    # PR11.4c (Break-Glass Audit Completion). See
    # docs/pr11-breakglass-audit-discovery.md (omnibioai-control-center).
    SSO_OVERRIDE_CREATED = "sso_override_created"
    SSO_OVERRIDE_REMOVED = "sso_override_removed"
    # #67 (SAML break-glass override). Own event types, not a reuse of
    # SSO_OVERRIDE_CREATED/REMOVED -- same "genuinely separate table/
    # resource_type" reasoning SAML_CONFIGURATION_CREATED/UPDATED and
    # SAML_ENFORCEMENT_CHANGED already established above: an audit event
    # needs to identify which config (and therefore which provider) was
    # affected, so it stays provider-specific even though the permission
    # (override_sso_enforcement) and request schema (SSOOverrideRequest)
    # gating this action are deliberately shared across both providers --
    # see app/api/routes_org_saml.py's override endpoints for that rule.
    SAML_OVERRIDE_CREATED = "saml_override_created"
    SAML_OVERRIDE_REMOVED = "saml_override_removed"
    # #443: a trusted internal service (svc-bio-agent, holding
    # service_token.mint) minted a real access token on behalf of
    # another user. actor_user_id is the calling service's own user id,
    # target_user_id is whoever the token was minted for -- distinct
    # identities, same as SSO_OVERRIDE_CREATED's actor-vs-org distinction,
    # so the audit trail can always tell who did this and to whom.
    SERVICE_TOKEN_MINTED = "service_token_minted"
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
    # PR11.5.3 (Enterprise MFA Login Challenge). See
    # docs/pr11-mfa-login-challenge-discovery.md SS10.
    MFA_CHALLENGE_REQUIRED = "mfa_challenge_required"
    MFA_VERIFIED = "mfa_verified"
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"
    # PR11.5.4 (Enterprise MFA Recovery Codes + Admin Reset). See
    # docs/pr11-mfa-recovery-codes-discovery.md SS4.
    MFA_RECOVERY_CODES_GENERATED = "mfa_recovery_codes_generated"
    MFA_RECOVERY_CODES_REGENERATED = "mfa_recovery_codes_regenerated"
    MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
    MFA_RESET_BY_ADMIN = "mfa_reset_by_admin"
    # PR11.5.5 (Enterprise Organization MFA Policy). See
    # docs/pr11-mfa-org-policy-discovery.md SS7.
    MFA_POLICY_ENABLED = "mfa_policy_enabled"
    MFA_POLICY_DISABLED = "mfa_policy_disabled"
    MFA_POLICY_OVERRIDE_CREATED = "mfa_policy_override_created"
    MFA_POLICY_OVERRIDE_REMOVED = "mfa_policy_override_removed"
    # PR13 (Dynamic Permission Assignment & Enterprise RBAC Activation).
    # Emitted whenever role_service rejects an attempt to create/edit a
    # custom org role with a GLOBAL-scope permission, or to assign a role
    # carrying a GLOBAL-scope permission to an org member -- both are
    # privilege-escalation attempts, not ordinary validation failures, so
    # they get their own trail rather than just surfacing as a 400/403
    # with nothing recorded server-side.
    ROLE_ASSIGNMENT_DENIED = "role_assignment_denied"
    # HIPAA Phase 1 PR1 (Authentication Abuse Protection). Emitted once
    # per dimension (account/ip/pair) each time that dimension's lockout
    # is newly triggered -- not on every throttled attempt while a
    # lockout is already active, to avoid audit-log amplification during
    # a sustained attack. See app/services/login_throttle_service.py.
    AUTH_RATE_LIMIT_TRIGGERED = "auth_rate_limit_triggered"
    # HIPAA Phase 1 PR3 (Session Security Hardening). Discovery for this
    # PR found ZERO session-lifecycle events existed before it -- not
    # even for logout or manual self-service revocation. One event type,
    # not one per cause, mirroring LOGIN_FAILURE's own established
    # convention of a fixed `reason` value in metadata rather than a
    # family of near-duplicate event-type constants -- see
    # app/services/session_service.py's REASON_* constants for the full,
    # single vocabulary (existing: user_logout/user_revoked/
    # reuse_detected; new: idle_timeout/absolute_timeout/
    # concurrent_session_limit/account_disabled). See
    # app/services/auth_service.py's `_log_session_revoked` for the one
    # place this is emitted from.
    SESSION_REVOKED = "session_revoked"
    # HIPAA Phase 3 (MFA/TOTP Challenge Throttling). Same "once per
    # dimension, only on the request that newly crosses that dimension's
    # threshold" convention as AUTH_RATE_LIMIT_TRIGGERED above -- a
    # distinct event type, not a reuse of that one, since this is a
    # different resource (an MFA challenge attempt, not a password login
    # attempt) with its own dimensions/thresholds. See
    # app/services/mfa_throttle_service.py.
    MFA_RATE_LIMIT_TRIGGERED = "mfa_rate_limit_triggered"


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
