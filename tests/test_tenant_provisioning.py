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
