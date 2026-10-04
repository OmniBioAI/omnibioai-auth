"""M17 (design audit gap #9's remaining bullet): self-service API-key
creation should require the organization to have an active billing
plan. The gate itself lives in routes_apikeys.py; this module is the
one cross-service call it needs -- omnibioai-billing owns subscription
state, omnibioai-auth doesn't duplicate it.

Calls omnibioai-billing's existing GET /billing/organizations/{id}/subscription
(no new billing-service endpoint, no new shared secret): that route
already accepts any validly-signed platform JWT whose org_id claim
matches the organization being queried (see omnibioai-billing's
app/core/iam.py::get_authorized_organization_id) -- the same signing
key this service already uses for every real session token. A
synthetic, minimal, single-use token is minted here (via the same
create_access_token every login already calls) purely to satisfy that
check; it is used for this one outbound call and never stored, logged,
or returned to any caller.

Auto-enrollment means this call itself creates a Free-plan subscription
for an organization that has never had one at all (see
omnibioai-billing's auto_enrollment_service.py, invoked inside
get_subscription_summary) -- so a brand-new organization's very first
self-service key creation still succeeds; the gate only ever actually
blocks an organization whose subscription has gone to "suspended"
(mid payment-failure grace period) or "cancelled".
"""
import httpx

from app.core.config import settings
from app.core.jwt import create_access_token

_ACTIVE_STATUSES = {"active", "trial"}


def organization_has_active_plan(organization_id: int) -> bool:
    """Fails OPEN (True) on any billing-service error (timeout,
    connection refused, non-2xx, malformed response) -- an outage in a
    service this one doesn't own must never block self-service key
    creation. This is an availability-vs-business-gate tradeoff
    deliberately decided the same direction every other cross-service
    check in this project's wider system has gone (quota/rate-limit
    checks all fail open too); it is not a billing-critical path the
    way an actual metered usage event is.
    """
    token = create_access_token({
        "sub": "system:billing-plan-check",
        "email": "",
        "roles": [],
        "permissions": [],
        "org_id": organization_id,
        "org_role": [],
        "auth_method": "service",
    })
    try:
        resp = httpx.get(
            f"{settings.BILLING_SERVICE_URL}/billing/organizations/{organization_id}/subscription",
            headers={"Authorization": f"Bearer {token}"},
            timeout=3,
        )
    except httpx.HTTPError:
        return True
    if resp.status_code == 404:
        # NoActiveSubscriptionError -- auto-enrollment should make this
        # unreachable in practice (see module docstring), but if it ever
        # happens, "no subscription at all" is not an active plan.
        return False
    if resp.status_code != 200:
        return True
    try:
        return resp.json().get("status") in _ACTIVE_STATUSES
    except ValueError:
        return True
