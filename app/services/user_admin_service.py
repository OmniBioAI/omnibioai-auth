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

from app.db.models import OrganizationMembership, User
from app.schemas.user_admin import ALLOWED_USER_STATUSES

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
) -> tuple[list[dict], int]:
    """Returns (page of summary dicts, total matching users). Assumes
    page/page_size/sort_by/sort_order are already validated -- see
    routes_platform_users.py, which owns HTTP-level input validation.
    """
    query = db.query(User)
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))

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

    if status != user.status:
        user.status = status
        user.status_changed_at = datetime.utcnow()
        user.status_changed_reason = reason
        user.status_changed_by_user_id = actor_user_id

    db.commit()
    db.refresh(user)
    return user
