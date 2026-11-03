from app.services.tenant_provisioning_service import membership_plan_for_license


def test_beta_license_maps_to_free_membership():
    assert membership_plan_for_license('beta') == 'free'
