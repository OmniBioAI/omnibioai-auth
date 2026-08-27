"""PR4 (Enterprise IAM Foundation): coverage for the Permission Registry
(app/core/permission_names.py) itself -- independent of any HTTP route.
Route-level (POST/PUT /roles) validation behavior is covered in
tests/test_roles.py alongside the rest of the role CRUD suite.

PR6 additions: filter_registry()/registry_stats() (pure in-memory query
helpers) get their own unit coverage here too, independent of the
GET /platform/permissions HTTP wrapper (covered in
tests/test_platform_permissions_api.py).
"""

from app.core.permission_names import (
    REGISTRY,
    PermissionCategory,
    PermissionScope,
    filter_registry,
    is_known_permission,
    is_valid_permission_format,
    list_registry,
    registry_stats,
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
    "model.use": PermissionCategory.MODEL,
    "dataset.read": PermissionCategory.DATASET,
    "usage.read": PermissionCategory.BILLING,
    "billing.read": PermissionCategory.BILLING,
    "billing.manage": PermissionCategory.BILLING,
    "subscription.manage": PermissionCategory.BILLING,
    "marketplace.install": PermissionCategory.MARKETPLACE,
}

# omnibioai-workflow-bundles IAM integration: unlike FUTURE_NAMES above,
# these are not unenforced placeholders -- they're consumed immediately by
# that repo's require_permission dependency, so they don't carry the
# "Reserved -- not yet enforced" description and get their own assertions
# below rather than being folded into the FUTURE_NAMES checks.
WORKFLOW_BUNDLES_NAMES = {
    "workflow.read": PermissionCategory.WORKFLOW,
    "workflow.publish": PermissionCategory.WORKFLOW,
    "workflow.manage": PermissionCategory.WORKFLOW,
}

# omnibioai-tes IAM integration: same "real, immediately-enforced" shape as
# WORKFLOW_BUNDLES_NAMES above, not FUTURE_NAMES -- workflow.execute (which
# used to be an unenforced placeholder, hence its old home in FUTURE_NAMES)
# now gates omnibioai-tes's submit/validate/cancel routes, and runs.read is
# a new addition gating that repo's read-only run history/status/logs/
# results endpoints. Neither carries the "Reserved -- not yet enforced"
# description any more.
TES_NAMES = {
    "workflow.execute": PermissionCategory.WORKFLOW,
    "runs.read": PermissionCategory.WORKFLOW,
}

# omnibioai-model-registry Phase 2E integration: same "real, immediately-
# enforced" shape as WORKFLOW_BUNDLES_NAMES/TES_NAMES above -- gates that
# repo's POST /v1/ownership/resolve endpoint (legacy/unowned model
# ownership resolution), independent of model.use. Not a FUTURE_NAMES-
# style unenforced placeholder.
MODEL_REGISTRY_OWNERSHIP_NAMES = {
    "model.resolve_ownership": PermissionCategory.MODEL,
}

# Model Registry read/use authorization split audit: same "real,
# immediately-enforced" shape as MODEL_REGISTRY_OWNERSHIP_NAMES above --
# gates that repo's genuinely read-only catalog routes (GET /v1/models,
# /v1/aliases, /v1/compare, /v1/metrics, /v1/runs/get, /v1/runs/list),
# checked as "model.use OR model.read" so no existing model.use holder
# loses access. Not a FUTURE_NAMES-style unenforced placeholder, and not
# layered into MODEL_REGISTRY_OWNERSHIP_NAMES above -- that set is
# specifically the Phase 2E ownership-resolution permission, an unrelated
# administrative capability.
MODEL_REGISTRY_READ_NAMES = {
    "model.read": PermissionCategory.MODEL,
}

# #443 (session/allauth users have no JWT to forward to TES): same "real,
# immediately-enforced" shape as MODEL_REGISTRY_OWNERSHIP_NAMES above --
# gates POST /service/mint-user-token, granted to exactly one dedicated
# role/account (bio_agent_service / svc-bio-agent), never to "scientist".
# Not a FUTURE_NAMES-style unenforced placeholder.
SERVICE_MINT_NAMES = {
    "service_token.mint": PermissionCategory.PLATFORM,
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


# ── omnibioai-workflow-bundles permissions ──────────────────────────────────

def test_all_workflow_bundles_names_are_known_not_legacy_scope_both():
    for name, category in WORKFLOW_BUNDLES_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.BOTH
        assert entry.category == category
        assert entry.deprecated is False


def test_all_workflow_bundles_names_pass_format_validation():
    for name in WORKFLOW_BUNDLES_NAMES:
        assert is_valid_permission_format(name), name


def test_workflow_bundles_names_are_not_marked_reserved():
    # These are real, immediately-enforced permissions (first consumer:
    # omnibioai-workflow-bundles), not unenforced placeholders like
    # FUTURE_NAMES -- so they must not carry that description.
    for name in WORKFLOW_BUNDLES_NAMES:
        assert "not yet enforced" not in REGISTRY[name].description.lower()


# ── omnibioai-tes permissions ────────────────────────────────────────────────

def test_all_tes_names_are_known_not_legacy_scope_both():
    for name, category in TES_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.BOTH
        assert entry.category == category
        assert entry.deprecated is False


def test_all_tes_names_pass_format_validation():
    for name in TES_NAMES:
        assert is_valid_permission_format(name), name


def test_tes_names_are_not_marked_reserved():
    # Real, immediately-enforced permissions (omnibioai-tes), same shape as
    # WORKFLOW_BUNDLES_NAMES above -- must not carry the FUTURE_NAMES
    # "Reserved -- not yet enforced" description.
    for name in TES_NAMES:
        assert "not yet enforced" not in REGISTRY[name].description.lower()


# ── omnibioai-model-registry permissions ────────────────────────────────────

def test_all_model_registry_ownership_names_are_known_not_legacy_scope_both():
    for name, category in MODEL_REGISTRY_OWNERSHIP_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.BOTH
        assert entry.category == category
        assert entry.deprecated is False


def test_all_model_registry_ownership_names_pass_format_validation():
    for name in MODEL_REGISTRY_OWNERSHIP_NAMES:
        assert is_valid_permission_format(name), name


def test_model_registry_ownership_names_are_not_marked_reserved():
    # Real, immediately-enforced permission (omnibioai-model-registry Phase
    # 2E), same shape as WORKFLOW_BUNDLES_NAMES/TES_NAMES above -- must not
    # carry the FUTURE_NAMES "Reserved -- not yet enforced" description.
    for name in MODEL_REGISTRY_OWNERSHIP_NAMES:
        assert "not yet enforced" not in REGISTRY[name].description.lower()


def test_all_model_registry_read_names_are_known_not_legacy_scope_both():
    for name, category in MODEL_REGISTRY_READ_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.BOTH
        assert entry.category == category
        assert entry.deprecated is False


def test_all_model_registry_read_names_pass_format_validation():
    for name in MODEL_REGISTRY_READ_NAMES:
        assert is_valid_permission_format(name), name


def test_model_registry_read_names_are_not_marked_reserved():
    # Real, immediately-enforced permission (Model Registry read/use split
    # audit), same shape as MODEL_REGISTRY_OWNERSHIP_NAMES above -- must
    # not carry the FUTURE_NAMES "Reserved -- not yet enforced" description.
    for name in MODEL_REGISTRY_READ_NAMES:
        assert "not yet enforced" not in REGISTRY[name].description.lower()


def test_model_read_is_independent_of_model_use():
    # model.read must not imply model.use, or vice versa -- two separate
    # registry entries with no relationship encoded anywhere in the
    # registry itself. model-registry's own enforcement (checked as
    # "model.use OR model.read") is what makes model.use a superset in
    # practice; the vocabulary layer here encodes no such relationship.
    assert "model.use" in REGISTRY
    assert "model.read" in REGISTRY
    assert REGISTRY["model.use"].name != REGISTRY["model.read"].name
    assert REGISTRY["model.read"].description != REGISTRY["model.use"].description


def test_all_service_mint_names_are_known_not_legacy_scope_global():
    # Unlike every other non-legacy group above (all BOTH-scoped),
    # service_token.mint is GLOBAL -- checked purely via require_permission
    # against the JWT permissions claim, never against a live org
    # membership, since the calling service has no org-scoped relationship
    # to the target user's organization.
    for name, category in SERVICE_MINT_NAMES.items():
        assert is_known_permission(name), f"{name} missing from registry"
        entry = REGISTRY[name]
        assert entry.legacy is False
        assert entry.scope == PermissionScope.GLOBAL
        assert entry.category == category
        assert entry.deprecated is False


def test_all_service_mint_names_pass_format_validation():
    for name in SERVICE_MINT_NAMES:
        assert is_valid_permission_format(name), name


def test_service_mint_names_are_not_marked_reserved():
    for name in SERVICE_MINT_NAMES:
        assert "not yet enforced" not in REGISTRY[name].description.lower()


def test_model_resolve_ownership_is_independent_of_model_use():
    # model.use must not imply model.resolve_ownership, or vice versa --
    # they are two separate registry entries with no relationship encoded
    # anywhere in the registry itself (implication, if any, can only ever
    # come from role-grant data, never from this vocabulary layer).
    assert "model.use" in REGISTRY
    assert "model.resolve_ownership" in REGISTRY
    assert REGISTRY["model.use"].name != REGISTRY["model.resolve_ownership"].name
    assert REGISTRY["model.resolve_ownership"].description != REGISTRY["model.use"].description


# ── Registry-wide invariant ──────────────────────────────────────────────────

def test_every_non_legacy_entry_satisfies_permission_format():
    for perm in REGISTRY.values():
        if not perm.legacy:
            assert is_valid_permission_format(perm.name), (
                f"non-legacy entry {perm.name!r} fails resource.action format"
            )


def test_registry_contains_exactly_the_expected_names():
    assert set(REGISTRY.keys()) == (
        LEGACY_NAMES | set(FUTURE_NAMES.keys()) | set(WORKFLOW_BUNDLES_NAMES.keys())
        | set(TES_NAMES.keys()) | set(MODEL_REGISTRY_OWNERSHIP_NAMES.keys())
        | set(MODEL_REGISTRY_READ_NAMES.keys()) | set(SERVICE_MINT_NAMES.keys())
    )


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


# ── filter_registry() (PR6) ──────────────────────────────────────────────────

def test_filter_registry_no_filters_matches_list_registry():
    assert filter_registry() == list_registry()


def test_filter_registry_by_category():
    results = filter_registry(category=PermissionCategory.BILLING)
    assert {p.name for p in results} == {
        "usage.read", "billing.read", "billing.manage", "subscription.manage",
    }


def test_filter_registry_by_scope():
    results = filter_registry(scope=PermissionScope.ORG)
    assert {p.name for p in results} == {
        "manage_org", "manage_teams", "manage_api_keys", "manage_oauth_clients", "manage_sso",
    }


def test_filter_registry_by_legacy():
    results = filter_registry(legacy=False)
    assert {p.name for p in results} == {p.name for p in REGISTRY.values() if not p.legacy}
    assert all(not p.legacy for p in results)


def test_filter_registry_by_deprecated():
    # Nothing is deprecated yet -- deprecated=True must return an empty list,
    # deprecated=False must return everything.
    assert filter_registry(deprecated=True) == []
    assert len(filter_registry(deprecated=False)) == len(REGISTRY)


def test_filter_registry_by_search_matches_name_case_insensitively():
    results = filter_registry(search="MODEL")
    names = {p.name for p in results}
    assert "model.use" in names


def test_filter_registry_by_search_matches_description():
    results = filter_registry(search="break-glass")
    assert {p.name for p in results} == {"override_sso_enforcement"}


def test_filter_registry_combines_filters_with_and_semantics():
    results = filter_registry(category=PermissionCategory.BILLING, legacy=False)
    assert {p.name for p in results} == {
        "usage.read", "billing.read", "billing.manage", "subscription.manage",
    }
    # #443: service_token.mint is the first non-legacy PLATFORM entry --
    # every other PLATFORM-category permission predates the registry.
    results2 = filter_registry(category=PermissionCategory.PLATFORM, legacy=False)
    assert {p.name for p in results2} == {"service_token.mint"}


def test_filter_registry_results_stay_sorted():
    results = filter_registry(scope=PermissionScope.BOTH)
    names = [p.name for p in results]
    assert names == sorted(names)


# ── registry_stats() (PR6) ───────────────────────────────────────────────────

def test_registry_stats_totals_match_registry_size():
    stats = registry_stats()
    assert stats["total_permissions"] == len(REGISTRY)
    assert stats["legacy_permissions"] + stats["future_permissions"] == len(REGISTRY)
    assert stats["legacy_permissions"] == len(LEGACY_NAMES)
    assert stats["future_permissions"] == (
        len(FUTURE_NAMES) + len(WORKFLOW_BUNDLES_NAMES) + len(TES_NAMES)
        + len(MODEL_REGISTRY_OWNERSHIP_NAMES) + len(MODEL_REGISTRY_READ_NAMES)
        + len(SERVICE_MINT_NAMES)
    )


def test_registry_stats_deprecated_count_is_zero_today():
    assert registry_stats()["deprecated_permissions"] == 0


def test_registry_stats_by_scope_sums_to_total():
    stats = registry_stats()
    assert sum(stats["by_scope"].values()) == stats["total_permissions"]
    assert stats["by_scope"]["org"] == 5
    # 7 pre-#443 GLOBAL entries (all legacy) + 1 (service_token.mint,
    # #443's own new non-legacy GLOBAL entry -- see SERVICE_MINT_NAMES
    # above, the first non-legacy permission in this registry that isn't
    # BOTH-scoped).
    assert stats["by_scope"]["global"] == 9
    # 11 pre-runs.read + 1 (runs.read, added by the omnibioai-tes IAM
    # integration -- see TES_NAMES above) + 1 (model.resolve_ownership,
    # added by the omnibioai-model-registry Phase 2E integration -- see
    # MODEL_REGISTRY_OWNERSHIP_NAMES above) + 1 (model.read, added by the
    # Model Registry read/use authorization split audit -- see
    # MODEL_REGISTRY_READ_NAMES above).
    assert stats["by_scope"]["both"] == 14


def test_registry_stats_by_category_sums_to_total():
    stats = registry_stats()
    assert sum(stats["by_category"].values()) == stats["total_permissions"]
    assert stats["by_category"]["billing"] == 4
    assert stats["by_category"]["marketplace"] == 1
