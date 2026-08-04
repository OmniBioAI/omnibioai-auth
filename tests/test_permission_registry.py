"""PR4 (Enterprise IAM Foundation): coverage for the Permission Registry
(app/core/permission_names.py) itself -- independent of any HTTP route.
Route-level (POST/PUT /roles) validation behavior is covered in
tests/test_roles.py alongside the rest of the role CRUD suite.
"""

from app.core.permission_names import (
    REGISTRY,
    PermissionCategory,
    PermissionScope,
    is_known_permission,
    is_valid_permission_format,
    list_registry,
)

LEGACY_NAMES = {
    "manage_roles",
    "manage_licenses",
    "manage_config",
    "override_sso_enforcement",
    "manage_all_orgs",
    "platform.manage_infra",
    "platform.manage_cron",
    "platform.manage_content",
    "manage_org",
    "manage_teams",
    "manage_api_keys",
    "manage_oauth_clients",
    "manage_sso",
}

FUTURE_NAMES = {
    "workflow.execute": PermissionCategory.WORKFLOW,
    "model.use": PermissionCategory.MODEL,
    "dataset.read": PermissionCategory.DATASET,
    "usage.read": PermissionCategory.BILLING,
    "billing.read": PermissionCategory.BILLING,
    "billing.manage": PermissionCategory.BILLING,
    "subscription.manage": PermissionCategory.BILLING,
    "marketplace.install": PermissionCategory.MARKETPLACE,
}

GLOBAL_LEGACY_NAMES = {
    "manage_roles",
    "manage_licenses",
    "manage_config",
    "override_sso_enforcement",
    "manage_all_orgs",
    "platform.manage_infra",
    "platform.manage_cron",
    "platform.manage_content",
}

ORG_LEGACY_NAMES = {
    "manage_org",
    "manage_teams",
    "manage_api_keys",
    "manage_oauth_clients",
    "manage_sso",
}


# ── Legacy names ─────────────────────────────────────────────────────────────

def test_all_legacy_names_are_known_and_marked_legacy():
    for name in LEGACY_NAMES:
        assert is_known_permission(name), f"{name} missing from registry"
        assert REGISTRY[name].legacy is True
        assert REGISTRY[name].deprecated is False


def test_legacy_names_have_expected_enforcement_scope():
    for name in GLOBAL_LEGACY_NAMES:
        assert REGISTRY[name].scope == PermissionScope.GLOBAL, name
    for name in ORG_LEGACY_NAMES:
        assert REGISTRY[name].scope == PermissionScope.ORG, name


def test_legacy_names_categorized_platform_or_organization():
    for name in GLOBAL_LEGACY_NAMES:
        assert REGISTRY[name].category == PermissionCategory.PLATFORM, name
    for name in ORG_LEGACY_NAMES:
        assert REGISTRY[name].category == PermissionCategory.ORGANIZATION, name


def test_legacy_names_exempt_from_format_check_where_applicable():
    # Several legacy names (e.g. manage_org) are not resource.action shaped.
    # They must still be valid, known permissions.
    assert not is_valid_permission_format("manage_org")
    assert is_known_permission("manage_org")


# ── Future enterprise permissions ───────────────────────────────────────────

def test_all_future_names_are_known_not_legacy_scope_both():
    for name, category in FUTURE_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.BOTH
        assert entry.category == category
        assert entry.deprecated is False


def test_all_future_names_pass_format_validation():
    for name in FUTURE_NAMES:
        assert is_valid_permission_format(name), name


def test_future_names_have_reserved_description():
    for name in FUTURE_NAMES:
        assert "not yet enforced" in REGISTRY[name].description.lower()


# ── Registry-wide invariant ──────────────────────────────────────────────────

def test_every_non_legacy_entry_satisfies_permission_format():
    for perm in REGISTRY.values():
        if not perm.legacy:
            assert is_valid_permission_format(perm.name), (
                f"non-legacy entry {perm.name!r} fails resource.action format"
            )


def test_registry_contains_exactly_the_expected_names():
    assert set(REGISTRY.keys()) == LEGACY_NAMES | set(FUTURE_NAMES.keys())


# ── Format validation examples ───────────────────────────────────────────────

def test_is_valid_permission_format_accepts_resource_action_shape():
    assert is_valid_permission_format("billing.read")
    assert is_valid_permission_format("workflow.execute")


def test_is_valid_permission_format_rejects_malformed_examples():
    for bad in ["billing", ".billing.read", "billing.", "Billing.read", "billing-read"]:
        assert not is_valid_permission_format(bad), bad


def test_is_known_permission_false_for_unregistered_name():
    assert not is_known_permission("not_a_real_permission")


# ── Serialization ────────────────────────────────────────────────────────────

def test_as_dict_contains_all_expected_fields_for_legacy_entry():
    d = REGISTRY["manage_org"].as_dict()
    assert d == {
        "name": "manage_org",
        "resource": "org",
        "action": "manage",
        "scope": "org",
        "category": "organization",
        "description": REGISTRY["manage_org"].description,
        "legacy": True,
        "deprecated": False,
        "deprecated_reason": None,
    }


def test_as_dict_contains_all_expected_fields_for_future_entry():
    d = REGISTRY["billing.read"].as_dict()
    assert set(d.keys()) == {
        "name", "resource", "action", "scope", "category",
        "description", "legacy", "deprecated", "deprecated_reason",
    }
    assert d["name"] == "billing.read"
    assert d["resource"] == "billing"
    assert d["action"] == "read"
    assert d["scope"] == "both"
    assert d["category"] == "billing"
    assert d["legacy"] is False
    assert d["deprecated"] is False
    assert d["deprecated_reason"] is None


def test_list_registry_is_sorted_by_name():
    names = [p.name for p in list_registry()]
    assert names == sorted(names)
    assert len(names) == len(REGISTRY)
