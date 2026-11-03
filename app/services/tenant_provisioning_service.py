"""Non-blocking Auth hook for the Workbench-owned tenant orchestrator."""
import logging
from threading import Thread

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)

LICENSE_PLAN_TO_MEMBERSHIP = {'beta': 'free'}


def membership_plan_for_license(license_plan: str) -> str:
    return LICENSE_PLAN_TO_MEMBERSHIP.get(license_plan, 'free')


def ensure_tenant(user_id: int) -> dict | None:
    try:
        response = httpx.post(
            settings.WORKBENCH_SERVICE_URL.rstrip('/') + f'/api/storage/internal/tenants/{user_id}/ensure',
            json={'dry_run': False},
            headers={'X-Tenant-Provisioning-Token': settings.TENANT_PROVISIONING_SERVICE_TOKEN},
            timeout=settings.TENANT_PROVISIONING_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        log.exception('tenant provisioning pending for user %s', user_id)
        return None


def schedule_ensure_tenant(user_id: int) -> None:
    """Daemon work cannot delay or fail activation/login; next login retries."""
    # An unconfigured environment cannot authenticate the internal call.
    # Keep the step pending for the next login after configuration instead of
    # creating an unbounded number of doomed network threads (especially in
    # test/CLI processes that perform many logins in one interpreter).
    if not settings.WORKBENCH_SERVICE_URL or not settings.TENANT_PROVISIONING_SERVICE_TOKEN:
        log.warning('tenant provisioning pending for user %s: service configuration missing', user_id)
        return
    try:
        Thread(target=ensure_tenant, args=(user_id,), name=f'tenant-provision-{user_id}', daemon=True).start()
    except Exception:
        log.exception('could not schedule tenant provisioning for user %s', user_id)
