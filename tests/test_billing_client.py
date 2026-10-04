"""app/services/billing_client.py: the one cross-service call behind
design audit gap #9's "self-service key creation gated on an active
billing plan." Mocks httpx.get directly -- no real omnibioai-billing
call is ever made in this suite.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from unittest.mock import MagicMock, patch

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

    assert captured["url"].endswith("/organizations/99/subscription")
    claims = decode_token(captured["token"])
    assert claims["org_id"] == 99
    assert claims["type"] == "access"
