"""app/services/billing_client.py: the one cross-service call behind
design audit gap #9's "self-service key creation gated on an active
billing plan." Mocks httpx.get directly -- no real omnibioai-billing
call is ever made in this suite. See
test_sends_a_token_scoped_to_the_requested_organization's own comment
for why that one assertion is an exact match, not endswith -- a
real-stack smoke test (not this mocked suite) is what actually caught
the URL this module originally called being wrong (missing billing-
service's own /billing router prefix), so every call it ever made 404'd
in production despite this whole suite passing throughout.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import MagicMock, patch

from app.core.config import settings
from app.services import billing_client


def _response(status_code, json_body=None, raises_on_json=False):
    resp = MagicMock()
    resp.status_code = status_code
    if raises_on_json:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = json_body or {}
    return resp


def test_active_status_is_true():
    with patch.object(billing_client.httpx, "get", return_value=_response(200, {"status": "active"})):
        assert billing_client.organization_has_active_plan(42) is True


def test_trial_status_is_true():
    with patch.object(billing_client.httpx, "get", return_value=_response(200, {"status": "trial"})):
        assert billing_client.organization_has_active_plan(42) is True


def test_suspended_status_is_false():
    with patch.object(billing_client.httpx, "get", return_value=_response(200, {"status": "suspended"})):
        assert billing_client.organization_has_active_plan(42) is False


def test_cancelled_status_is_false():
    with patch.object(billing_client.httpx, "get", return_value=_response(200, {"status": "cancelled"})):
        assert billing_client.organization_has_active_plan(42) is False


def test_404_no_subscription_at_all_is_false():
    """NoActiveSubscriptionError -- auto-enrollment should make this
    unreachable in practice, but a genuine "nothing at all" state is
    correctly not an active plan."""
    with patch.object(billing_client.httpx, "get", return_value=_response(404)):
        assert billing_client.organization_has_active_plan(42) is False


def test_network_error_fails_open():
    import httpx

    with patch.object(billing_client.httpx, "get", side_effect=httpx.ConnectError("refused")):
        assert billing_client.organization_has_active_plan(42) is True


def test_5xx_from_billing_service_fails_open():
    with patch.object(billing_client.httpx, "get", return_value=_response(500)):
        assert billing_client.organization_has_active_plan(42) is True


def test_malformed_json_response_fails_open():
    with patch.object(billing_client.httpx, "get", return_value=_response(200, raises_on_json=True)):
        assert billing_client.organization_has_active_plan(42) is True


def test_sends_a_token_scoped_to_the_requested_organization():
    from app.core.jwt import decode_token

    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["token"] = headers["Authorization"].removeprefix("Bearer ")
        return _response(200, {"status": "active"})

    with patch.object(billing_client.httpx, "get", side_effect=fake_get):
        billing_client.organization_has_active_plan(99)

    # Exact match, not endswith: billing-service's router is mounted at
    # /billing (app/routers/billing.py's own APIRouter(prefix="/billing")
    # in omnibioai-billing) -- a bare /organizations/99/subscription
    # also satisfies endswith(".../organizations/99/subscription") while
    # actually 404ing against the real service, which is exactly the bug
    # this exact-match assertion exists to catch (found via a live
    # integration check against the real billing-service, not by any
    # mocked unit test -- see this module's own git history).
    assert captured["url"] == f"{settings.BILLING_SERVICE_URL}/billing/organizations/99/subscription"
    claims = decode_token(captured["token"])
    assert claims["org_id"] == 99
    assert claims["type"] == "access"
