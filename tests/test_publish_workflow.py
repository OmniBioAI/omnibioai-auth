"""Regression checks for the Auth publisher/verifier workflow.

These checks intentionally inspect the workflow file's structure as text only
-- no YAML parsing dependency, no network, no Docker -- so they stay safe and
fast in ordinary unit-test jobs. They follow the same convention established
for ghcr.io/omnibioai/omnibioai-model-registry's publish workflow tests, and
exist to prevent recurrence of defects already proven real in that sibling
campaign (grep-based metadata checks against attestation-bearing multi-
manifest indices, QEMU standing in for native architecture evidence, runtime
smoke omitting required runtime configuration).

Developer:
    Manish Kumar <manish@omnibioai.org>
"""

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "publish-auth.yml"
)

CI_WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "ci.yml"
)


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _ci_workflow() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def test_publish_workflow_is_manual_dispatch_only() -> None:
    """Production releases must be a controlled, explicit action -- never a
    side effect of an ordinary branch/tag push."""
    text = _workflow()
    assert "workflow_dispatch:" in text
    assert "on:\n  push" not in text
    assert "tags: ['v*.*.*']" not in text


def test_publish_latest_defaults_to_false() -> None:
    text = _workflow()
    assert "default: false" in text
    assert 'if [ "${{ inputs.publish_latest }}" = true ]' in text


def test_source_sha_is_validated_fail_closed() -> None:
    text = _workflow()
    assert 'test "${#SOURCE_SHA}" -eq 40' in text
    assert "grep -Eq '^[0-9a-f]{40}$'" in text
    assert 'test "$SOURCE_SHA" = "$(git rev-parse HEAD)"' in text


def test_no_qemu_anywhere_in_release_workflow() -> None:
    """QEMU/emulation must never stand in for native architecture evidence."""
    text = _workflow()
    for token in ("setup-qemu-action", "tonistiigi/binfmt"):
        assert token not in text


def test_native_runner_assertions_for_both_architectures() -> None:
    text = _workflow()
    assert 'test "$(uname -m)" = x86_64' in text
    assert 'test "$(uname -m)" = aarch64' in text
    assert "runs-on: ubuntu-24.04-arm" in text


def test_both_architectures_built_and_published_independently() -> None:
    text = _workflow()
    assert "build_amd64:" in text
    assert "build_arm64:" in text
    assert "platforms: linux/amd64" in text
    assert "platforms: linux/arm64" in text
    # Never a single combined multi-platform buildx invocation (that path
    # requires QEMU on a single runner for the non-native architecture).
    assert "linux/amd64,linux/arm64" not in text


def test_metadata_is_resolved_from_the_platform_manifest_by_digest() -> None:
    """Mirrors the proven Model Registry fix: labels live on the platform
    image's own config, never on the attestation-bearing index's text
    rendering -- the verifier must resolve by digest/platform explicitly."""
    text = _workflow()
    assert 'select(.platform.os == "linux" and .platform.architecture == $arch)' in text
    assert "--format '{{json .Image.Config.Labels}}'" in text


def test_attestation_descriptors_are_not_mistaken_for_runtime_platforms() -> None:
    text = _workflow()
    assert 'select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")' in text
    assert 'select(.platform.os == "linux"' in text


def test_oci_revision_requires_exact_40_character_sha_not_substring() -> None:
    text = _workflow()
    assert 'test "${#actual_revision}" -eq 40' in text
    assert 'test "$actual_revision" = "$SOURCE_SHA"' in text


def test_supply_chain_attestations_are_subject_bound_not_merely_present() -> None:
    text = _workflow()
    assert 'test "$subject_digest" = "$runtime_digest"' in text
    assert "https://spdx.dev/Document" in text
    assert "https://slsa.dev/provenance/v1" in text


def test_github_native_attestation_api_is_not_relied_upon() -> None:
    assert "gh attestation verify" not in _workflow()


def test_runtime_smoke_pulls_immutable_digest_not_a_mutable_tag() -> None:
    text = _workflow()
    assert "needs.build_amd64.outputs.digest" in text
    assert "needs.build_arm64.outputs.digest" in text
    assert 'docker pull --platform linux/amd64 "$IMAGE@$DIGEST"' in text
    assert 'docker pull --platform linux/arm64 "$IMAGE@$DIGEST"' in text


def test_runtime_smoke_runs_after_release_verification() -> None:
    text = _workflow()
    assert "needs: [build_amd64, build_arm64, assemble_and_verify]" in text


def test_runtime_smoke_never_references_latest_tag() -> None:
    text = _workflow()
    smoke_start = text.index("smoke_amd64:")
    smoke_text = text[smoke_start:]
    assert ":latest" not in smoke_text


def test_runtime_smoke_jobs_are_fail_closed_and_bounded() -> None:
    text = _workflow()
    assert "timeout-minutes: 8" in text
    assert "curl -sf --max-time 3" in text
    assert "trap cleanup EXIT" in text


def test_runtime_smoke_supplies_mandatory_auth_runtime_configuration() -> None:
    """Auth's process cannot even finish importing without a reachable
    MySQL (app/main.py calls Base.metadata.create_all(bind=engine) at
    module level, unconditionally) and a valid AUTH_AUDIT_INTEGRITY_KEY
    (ensure_default_org_roles -> create_role -> audit_service.log_event
    signs an audit record at import time too) -- the smoke harness must
    stand up a real, ephemeral MySQL (and Redis, for full correctness)
    matching the production depends_on contract, and supply a valid
    integrity key, not bypass either requirement."""
    text = _workflow()
    smoke_start = text.index("smoke_amd64:")
    smoke_text = text[smoke_start:]
    for required_env in (
        "DB_HOST=mysql-smoke",
        "SECRET_KEY=",
        "AUTH_AUDIT_INTEGRITY_KEY=",
        "REDIS_URL=redis://redis-smoke",
    ):
        assert required_env in smoke_text
    assert "mysql:8.0" in smoke_text
    assert "redis:7" in smoke_text
    assert "mysqladmin ping" in smoke_text
    # No developer- or host-specific values, no host bind mount.
    assert "~" not in smoke_text
    assert "-v " not in smoke_text


def test_runtime_smoke_checks_auth_specific_endpoint_not_just_health() -> None:
    """Beyond bare process-up (/health), exercise one real, safe,
    non-mutating Auth code path: the public JWKS endpoint. Never creates
    users, changes credentials, or issues production credentials."""
    text = _workflow()
    assert "/.well-known/jwks.json" in text
    assert "AUTH_SMOKE=PASS" in text
    for forbidden in ("/auth/register", "/auth/login", "ADMIN_BOOTSTRAP_PASSWORD=real"):
        assert forbidden not in text


def test_ci_workflow_no_longer_builds_or_pushes_images() -> None:
    """Release publication lives solely in publish-auth.yml now -- ci.yml
    is lint/test hygiene on push/PR only."""
    text = _ci_workflow()
    assert "docker/build-push-action" not in text
    assert "setup-qemu-action" not in text
    assert "release:" not in text
