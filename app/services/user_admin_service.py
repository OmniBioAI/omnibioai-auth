"""Phase 3 PR3A: platform-admin user directory.

Mirrors platform_admin_service.py's own shape and performance discipline
exactly (Phase 3 PR1): the list endpoint must scale without turning into
an N+1 query storm, and no function here takes a caller identity --
authorization is entirely the route layer's job (require_permission
(MANAGE_ALL_ORGS), the same permission PR1's org directory already uses,
reused here rather than inventing a narrower one -- see this PR's
implementation report for that decision). Deliberately isolated from
org_service.py: this answers "every user in the system," not "members of
one org," a different question for a different caller than anything
org_service already provides.
"""
from datetime import datetime
from typing import Literal

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.db.models import MFADevice, MFARecoveryCode, OrganizationMembership, Role, User
from app.schemas.user_admin import ALLOWED_USER_STATUSES
from app.services import audit_service
from app.services.audit_service import AuditEventType

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

SortField = Literal["email", "created_at", "status"]
SortOrder = Literal["asc", "desc"]

_SORT_COLUMNS = {
    "email": User.email,
    "created_at": User.created_at,
    "status": User.status,
}


def _org_counts_by_user(db: Session, user_ids: list[int]) -> dict[int, int]:
    """One GROUP BY query: {user_id: org membership count} -- the same
    batched-aggregate pattern platform_admin_service.py's _counts_by_org
    uses, never one query per user."""
    if not user_ids:
        return {}
    rows = (
        db.query(OrganizationMembership.user_id, func.count(OrganizationMembership.id))
        .filter(OrganizationMembership.user_id.in_(user_ids))
        .group_by(OrganizationMembership.user_id)
        .all()
    )
    return dict(rows)


def list_users(
    db: Session,
    page: int,
    page_size: int,
    search: str | None,
    sort_by: SortField,
    sort_order: SortOrder,
    organization_id: int | None = None,
    status: str | None = None,
    role: str | None = None,
) -> tuple[list[dict], int]:
    """Returns (page of summary dicts, total matching users). Assumes
    page/page_size/sort_by/sort_order are already validated -- see
    routes_platform_users.py, which owns HTTP-level input validation.

    PR11.1 filters, each independent and AND-combined with the others:
      - `status`: exact match against User.status.
      - `organization_id`: only users with an OrganizationMembership row
        in that org.
      - `role`: two different things depending on whether
        `organization_id` is also given, matching how this codebase
        already models roles as two separate catalogs (global vs.
        org-scoped, see app/db/models.py's user_roles/membership_roles) --
        with an org_id, `role` matches the user's *role within that org*
        (membership_roles); without one, it matches a *global* role
        (user_roles). Asking "org_admin in org 7" and asking "has the
        global role org_admin" are different questions, so this filter
        answers whichever one the caller's other params imply.
    """
    query = db.query(User)
    joined_membership = False
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))
    if status:
        query = query.filter(User.status == status)
    if organization_id is not None:
        query = query.join(OrganizationMembership, OrganizationMembership.user_id == User.id).filter(
            OrganizationMembership.organization_id == organization_id
        )
        joined_membership = True
        if role:
            query = query.join(OrganizationMembership.roles).filter(Role.name == role)
    elif role:
        query = query.join(User.roles).filter(Role.name == role)

    if joined_membership or role:
        # A join can multiply User rows (e.g. more than one role
        # assignment matching `role`) -- collapse back to one row per
        # user before paginating/counting.
        query = query.distinct()

    total = query.count()

    sort_column = _SORT_COLUMNS[sort_by]
    sort_column = sort_column.desc() if sort_order == "desc" else sort_column.asc()

    # selectinload: one extra query for every page's users' roles via a
    # single IN-clause, not one query per user (N+1) -- global_roles below
    # reads an already-loaded relationship, never triggers a new query.
    users = (
        query.options(selectinload(User.roles))
        .order_by(sort_column)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    user_ids = [u.id for u in users]
    org_counts = _org_counts_by_user(db, user_ids)

    summaries = [
        {
            "id": u.id,
            "email": u.email,
            "status": u.status,
            "created_at": u.created_at,
            "global_roles": sorted(r.name for r in u.roles),
            "org_count": org_counts.get(u.id, 0),
            "last_login_at": u.last_login_at,
            "authentication_method": u.authentication_method,
            "mfa_enabled": u.mfa_enabled,
        }
        for u in users
    ]
    return summaries, total


def get_user_detail(db: Session, user_id: int) -> dict | None:
    """Single-user detail view -- scoped to one user, so a direct query
    for their memberships (with .organization/.roles already available
    via existing relationships) is the right call, not a performance
    risk. Read-only: no route calling this may mutate anything.
    """
    user = db.query(User).options(selectinload(User.roles)).filter(User.id == user_id).first()
    if user is None:
        return None

    status_changed_by = (
        db.query(User).filter(User.id == user.status_changed_by_user_id).first()
        if user.status_changed_by_user_id is not None
        else None
    )

    memberships = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.user_id == user_id)
        .all()
    )

    # PR11.5.6: two small, single-user-scoped queries (not a page of
    # users, so no N+1 risk the way list_users above must guard
    # against) -- never a TOTP secret or a recovery code, only
    # metadata/counts. See docs/pr11-5-6-security-ui-discovery.md SS6.1
    # (omnibioai-control-center).
    devices = (
        db.query(MFADevice)
        .filter(MFADevice.user_id == user_id, MFADevice.disabled_at.is_(None))
        .order_by(MFADevice.created_at)
        .all()
    )
    recovery_codes_remaining = (
        db.query(MFARecoveryCode)
        .filter(MFARecoveryCode.user_id == user_id, MFARecoveryCode.used_at.is_(None))
        .count()
    )

    return {
        "id": user.id,
        "email": user.email,
        "status": user.status,
        "created_at": user.created_at,
        "global_roles": sorted(r.name for r in user.roles),
        "memberships": [
            {
                "organization_id": m.organization_id,
                "organization_name": m.organization.name,
                "organization_slug": m.organization.slug,
                "roles": sorted(r.name for r in m.roles),
                "status": m.status,
                "joined_at": m.joined_at,
            }
            for m in memberships
        ],
        "status_changed_at": user.status_changed_at,
        "status_changed_reason": user.status_changed_reason,
        "status_changed_by_email": status_changed_by.email if status_changed_by else None,
        "last_login_at": user.last_login_at,
        "authentication_method": user.authentication_method,
        "mfa_enabled": user.mfa_enabled,
        "mfa_status": user.mfa_status,
        "mfa_primary_method": user.mfa_primary_method,
        "mfa_enabled_at": user.mfa_enabled_at,
        "mfa_last_verified_at": user.mfa_last_verified_at,
        "mfa_devices": [
            {
                "device_type": d.device_type,
                "label": d.label,
                "created_at": d.created_at,
                "last_used_at": d.last_used_at,
            }
            for d in devices
        ],
        "mfa_recovery_codes_remaining": recovery_codes_remaining,
    }


def set_user_status(
    db: Session,
    user: User,
    status: str,
    reason: str | None,
    actor_user_id: int,
) -> User:
    """Mirrors org_service.update_organization's status-handling exactly
    (Phase 3 PR2): validates the value, only touches the tracking columns
    on an actual change, raises ValueError for an unrecognized status
    (mapped to 400 by the route). The caller (routes_platform_users.py)
    is responsible for confirming the actor holds manage_all_orgs before
    this is ever invoked -- this function validates the *value*, not who
    is allowed to set it.

    Unlike organization suspension (still a display-only flag as of PR2,
    nothing else in the platform enforces it), suspending a *user* takes
    effect immediately for that user's existing sessions: PR0.1's
    assert_token_usable already rejects any token for a non-"active"
    user, and PR0.2's refresh rebuilds claims from the database on every
    use, so a suspended user's next authenticated request or refresh --
    whichever comes first -- is rejected. No new enforcement code is
    needed here; this function only flips the same column those two
    already check.
    """
    if status not in ALLOWED_USER_STATUSES:
        raise ValueError(f"Unknown status: {status!r} (expected one of {sorted(ALLOWED_USER_STATUSES)})")

    changed = status != user.status
    before_status = user.status

    if changed:
        user.status = status
        user.status_changed_at = datetime.utcnow()
        user.status_changed_reason = reason
        user.status_changed_by_user_id = actor_user_id

    db.commit()
    db.refresh(user)

    if changed:
        # PR11.4b: event *type* uses the task's requested enabled/
        # disabled framing; the stored before/after state keeps the
        # real active/suspended values verbatim -- see
        # docs/pr11-identity-audit-discovery.md §4a. No organization_id
        # -- this is a cross-tenant, platform-admin action with no
        # single org in scope.
        audit_service.log_event(
            db,
            AuditEventType.USER_ENABLED if status == "active" else AuditEventType.USER_DISABLED,
            actor_user_id=actor_user_id, target_user_id=user.id,
            resource_type="user", resource_id=user.id,
            before_state={"status": before_status}, after_state={"status": status},
            metadata={"reason": reason},
        )
    return user
