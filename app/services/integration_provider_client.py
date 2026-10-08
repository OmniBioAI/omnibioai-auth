"""Fail-closed client for Workbench-owned non-secret provider policy."""

import re

import httpx

from app.core.config import settings

_PROVIDER_ID = re.compile(r"^[a-z0-9_]{1,64}$")


class ProviderPolicyUnavailable(RuntimeError):
    pass


def get_provider_policy(provider_id: str) -> dict:
    if not isinstance(provider_id, str) or not _PROVIDER_ID.fullmatch(provider_id):
        raise ProviderPolicyUnavailable("Provider is not available.")
    secret = settings.INTEGRATION_CREDENTIAL_SERVICE_SECRET
    if not secret:
        raise ProviderPolicyUnavailable("Provider policy service is not configured.")
    try:
        response = httpx.get(
            f"{settings.WORKBENCH_PROVIDER_POLICY_BASE_URL}/{provider_id}/policy/",
            headers={"X-Integration-Credential-Service-Secret": secret},
            timeout=3.0,
        )
    except httpx.HTTPError as exc:
        raise ProviderPolicyUnavailable("Provider policy service is unavailable.") from exc
    if response.status_code != 200:
        raise ProviderPolicyUnavailable("Provider is not available.")
    policy = response.json()
    if policy.get("provider_id") != provider_id or not isinstance(policy.get("authentication"), dict):
        raise ProviderPolicyUnavailable("Provider policy response is invalid.")
    return policy
