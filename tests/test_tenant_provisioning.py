from unittest.mock import patch

from app.services.tenant_provisioning_service import (
    membership_plan_for_license,
    schedule_ensure_tenant,
)


def test_beta_license_maps_to_free_membership():
    assert membership_plan_for_license('beta') == 'free'


def test_unconfigured_provisioning_remains_pending_without_starting_thread():
    with patch('app.services.tenant_provisioning_service.settings') as settings, \
         patch('app.services.tenant_provisioning_service.Thread') as thread:
        settings.WORKBENCH_SERVICE_URL = 'http://workbench:8000'
        settings.TENANT_PROVISIONING_SERVICE_TOKEN = ''
        schedule_ensure_tenant(42)
    thread.assert_not_called()


def test_disabled_direct_call_has_no_network_or_error_log(caplog):
    from app.services.tenant_provisioning_service import ensure_tenant
    with patch('app.services.tenant_provisioning_service.settings') as settings, \
         patch('app.services.tenant_provisioning_service.httpx.post') as post:
        settings.TENANT_PROVISIONING_SERVICE_TOKEN = ''
        assert ensure_tenant(42) is None
        schedule_ensure_tenant(42)
    post.assert_not_called()
    assert not [r for r in caplog.records if r.levelname in ('WARNING', 'ERROR', 'CRITICAL')]
