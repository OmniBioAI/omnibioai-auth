"""Phase 3 PR1: platform-admin organization discovery.

Deliberately isolated from org_service.py: that module answers per-caller,
per-org questions ("orgs *I* belong to", "is *this* org_id valid for me")
for any authenticated user. This module answers a different question --
"every organization that exists" -- and is only ever reached through
require_permission(MANAGE_ALL_ORGS) (app/api/routes_platform_admin.py),
never through org membership. No function here takes a caller identity at
all; authorization is entirely the route layer's job.

Performance note (the load-bearing design choice for this file): the list
endpoint must scale to tens of thousands of organizations without turning
into an N+1 query storm. Every resource count (members/teams/api-keys/
oauth-clients/licenses) is computed with exactly one GROUP BY query per
resource type over the *current page's* organization IDs -- five queries
total, regardless of page size or how many organizations exist platform-
wide. Counts are never fetched by looping over organizations and querying
per-org.
"""
from typing import Literal

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.db.models import (
    ApiKey,
    LicenseKey,
    OAuthClient,
    Organization,
    OrganizationMFAPolicy,
    OrganizationMembership,
    OrganizationSSOConfig,
    Team,
    User,
)
from app.services import apikey_service, oauth_client_service, org_service, org_sso_service, team_service

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

SortField = Literal["name", "created_at", "status", "owner_email"]
SortOrder = Literal["asc", "desc"]

_SORT_COLUMNS = {
    "name": Organization.name,
    "created_at": Organization.created_at,
    "status": Organization.status,
    "owner_email": User.email,
}


def _counts_by_org(db: Session, model, org_ids: list[int], extra_filter=None) -> dict[int, int]:
    """One GROUP BY query: {organization_id: count} for every id in
    `org_ids` that has at least one matching row. Callers treat a missing
    key as zero -- see list_organizations below."""
    if not org_ids:
        return {}
    query = db.query(model.organization_id, func.count(model.id)).filter(
        model.organization_id.in_(org_ids)
    )
    if extra_filter is not None:
        query = query.filter(extra_filter)
    return dict(query.group_by(model.organization_id).all())


def _org_ids_with_sso(db: Session, org_ids: list[int]) -> set[int]:
    if not org_ids:
        return set()
    rows = (
        db.query(OrganizationSSOConfig.organization_id)
        .filter(OrganizationSSOConfig.organization_id.in_(org_ids))
        .all()
    )
    return {r[0] for r in rows}


def _org_ids_requiring_mfa(db: Session, org_ids: list[int]) -> set[int]:
    """PR11.5.6 (discovery §6.2): same shape as _org_ids_with_sso above,
    scoped to policies with required=True -- an existing-but-disabled
    OrganizationMFAPolicy row (required=False) does not count."""
    if not org_ids:
        return set()
    rows = (
        db.query(OrganizationMFAPolicy.organization_id)
        .filter(
            OrganizationMFAPolicy.organization_id.in_(org_ids),
            OrganizationMFAPolicy.required.is_(True),
        )
        .all()
    )
    return {r[0] for r in rows}


def _org_ids_with_mfa_policy(db: Session, org_ids: list[int]) -> set[int]:
    """PR11.5.6: distinct from _org_ids_requiring_mfa above -- true iff
    any OrganizationMFAPolicy row exists at all, regardless of its
    `required` value. The Security Dashboard's "organizations without an
    MFA policy" tile needs this (an org with a row but required=False
    has *configured* a policy, just not turned it on -- a different,
    narrower fact than "never configured one")."""
    if not org_ids:
        return set()
    rows = (
        db.query(OrganizationMFAPolicy.organization_id)
        .filter(OrganizationMFAPolicy.organization_id.in_(org_ids))
        .all()
    )
    return {r[0] for r in rows}


def list_organizations(
    db: Session,
    page: int,
    page_size: int,
    search: str | None,
    sort_by: SortField,
    sort_order: SortOrder,
) -> tuple[list[dict], int]:
    """Returns (page of summary dicts, total matching organizations).
    Assumes `page`/`page_size`/`sort_by`/`sort_order` are already
    validated -- see routes_platform_admin.py, which owns HTTP-level
    input validation so this function can assume valid, in-range input.
    """
    base = db.query(Organization, User.email).outerjoin(
        User, Organization.created_by_user_id == User.id
    )

    if search:
        like = f"%{search}%"
        base = base.filter(or_(Organization.name.ilike(like), User.email.ilike(like)))

    total = base.count()

    sort_column = _SORT_COLUMNS[sort_by]
    sort_column = sort_column.desc() if sort_order == "desc" else sort_column.asc()

    rows = (
        base.order_by(sort_column)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    org_ids = [org.id for org, _ in rows]

    member_counts = _counts_by_org(db, OrganizationMembership, org_ids)
    team_counts = _counts_by_org(db, Team, org_ids)
    # Active-only for api-keys/oauth-clients/licenses: a platform admin
    # scanning this list is asking "how much is this org actually using
    # right now," not "how many keys have ever existed including revoked
    # ones" -- member_count stays unfiltered by status to match the
    # existing GET /orgs/{org_id}/members behavior (org_service.list_
    # members returns active+invited alike), so this list doesn't invent
    # a stricter definition of "member" than the rest of the API already
    # uses.
    api_key_counts = _counts_by_org(db, ApiKey, org_ids, ApiKey.status == "active")
    oauth_client_counts = _counts_by_org(db, OAuthClient, org_ids, OAuthClient.status == "active")
    license_counts = _counts_by_org(db, LicenseKey, org_ids, LicenseKey.revoked_at.is_(None))
    sso_org_ids = _org_ids_with_sso(db, org_ids)
    mfa_required_org_ids = _org_ids_requiring_mfa(db, org_ids)
    mfa_configured_org_ids = _org_ids_with_mfa_policy(db, org_ids)

    summaries = [
        {
            "id": org.id,
            "name": org.name,
            "status": org.status,
            "created_at": org.created_at,
            "owner_email": owner_email,
            "member_count": member_counts.get(org.id, 0),
            "team_count": team_counts.get(org.id, 0),
            "api_key_count": api_key_counts.get(org.id, 0),
            "oauth_client_count": oauth_client_counts.get(org.id, 0),
            "license_count": license_counts.get(org.id, 0),
            "sso_enabled": org.id in sso_org_ids,
            "mfa_policy_required": org.id in mfa_required_org_ids,
            "mfa_policy_configured": org.id in mfa_configured_org_ids,
        }
        for org, owner_email in rows
    ]
    return summaries, total


def get_organization_detail(db: Session, org_id: int) -> dict | None:
    """Single-organization detail view. Unlike list_organizations above,
    this is scoped to exactly one org, so reusing the existing per-org
    service functions (org_service.list_members, team_service.list_teams,
    etc.) is the right call, not a performance risk -- those functions
    already exist and are already correct; duplicating their queries here
    would be the actual mistake. Read-only: no route calling this may
    mutate anything.
    """
    org = org_service.get_organization(db, org_id)
    if org is None:
        return None

    owner = (
        db.query(User).filter(User.id == org.created_by_user_id).first()
        if org.created_by_user_id is not None
        else None
    )
    status_changed_by = (
        db.query(User).filter(User.id == org.status_changed_by_user_id).first()
        if org.status_changed_by_user_id is not None
        else None
    )

    memberships = org_service.list_members(db, org_id)
    teams = team_service.list_teams(db, org_id)
    api_keys = apikey_service.list_api_keys(db, org_id)
    oauth_clients = oauth_client_service.list_oauth_clients(db, org_id)
    licenses = db.query(LicenseKey).filter(LicenseKey.organization_id == org_id).all()
    sso_config = org_sso_service.get_sso_config(db, org_id)

    member_summary = {
        "total": len(memberships),
        "active": sum(1 for m in memberships if m.status == "active"),
        "invited": sum(1 for m in memberships if m.status == "invited"),
        "most_recent_at": max((m.joined_at for m in memberships), default=None),
    }
    team_summary = {
        "total": len(teams),
        "most_recent_at": max((t.created_at for t in teams), default=None),
    }
    api_key_summary = {
        "total": len(api_keys),
        "active": sum(1 for k in api_keys if k.status == "active"),
        "revoked": sum(1 for k in api_keys if k.status == "revoked"),
        "most_recent_at": max((k.created_at for k in api_keys), default=None),
    }
    oauth_client_summary = {
        "total": len(oauth_clients),
        "active": sum(1 for c in oauth_clients if c.status == "active"),
        "revoked": sum(1 for c in oauth_clients if c.status == "revoked"),
        "most_recent_at": max((c.created_at for c in oauth_clients), default=None),
    }
    license_summary = {
        "total": len(licenses),
        "active": sum(1 for lic in licenses if lic.revoked_at is None),
        "revoked": sum(1 for lic in licenses if lic.revoked_at is not None),
    }
    sso_summary = {
        "configured": sso_config is not None,
        "provider_type": sso_config.provider_type if sso_config else None,
        "issuer": sso_config.issuer if sso_config else None,
        "status": sso_config.status if sso_config else None,
        "enforced": bool(sso_config.enforced) if sso_config else False,
        "override_active": (sso_config.sso_override_at is not None) if sso_config else False,
    }

    return {
        "id": org.id,
        "slug": org.slug,
        "name": org.name,
        "plan": org.plan,
        "status": org.status,
        "created_at": org.created_at,
        "owner_user_id": owner.id if owner else None,
        "owner_email": owner.email if owner else None,
        "member_summary": member_summary,
        "team_summary": team_summary,
        "api_key_summary": api_key_summary,
        "oauth_client_summary": oauth_client_summary,
        "license_summary": license_summary,
        "sso": sso_summary,
        "status_changed_at": org.status_changed_at,
        "status_changed_reason": org.status_changed_reason,
        "status_changed_by_email": status_changed_by.email if status_changed_by else None,
        "recent_activity": {
            "org_created_at": org.created_at,
            "most_recent_member_joined_at": member_summary["most_recent_at"],
            "most_recent_api_key_created_at": api_key_summary["most_recent_at"],
            "most_recent_oauth_client_created_at": oauth_client_summary["most_recent_at"],
        },
    }
