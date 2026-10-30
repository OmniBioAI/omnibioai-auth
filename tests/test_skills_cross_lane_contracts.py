"""Verify the recorded IAM, policy, and Security Audit Track B wire contracts."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.schemas.skills_identity import SkillsVerifiedIdentity
from app.services.skills_audit_receipts import (
    SecurityAuditReceiptClient,
    SkillsAuditReceiptError,
    SkillsAuditReceiptSettings,
)

WORKSPACE = Path(__file__).resolve().parents[2]
AUDIT_FIXTURE = (
    WORKSPACE / "omnibioai-security-audit/tests/fixtures/skills_audit_receipt_v1.json"
)
LANE_FIXTURES = WORKSPACE / "omnibioai-skills-trackb-impl/tests/fixtures/cross_lane"
TEST_SIGNING_SEED = bytes(range(32))
TEST_KEY_ID = "skills-receipt-test-v1"


def _receipt_client(*, live=True, kill_switch=False, keys=None, post=None, token_file=""):
    public_key = Ed25519PrivateKey.from_private_bytes(TEST_SIGNING_SEED).public_key()
    raw_public_key = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return SecurityAuditReceiptClient(
        url="https://audit.invalid/receipts",
        token_file=token_file,
        verification_keys=keys if keys is not None else {TEST_KEY_ID: raw_public_key},
        settings=SkillsAuditReceiptSettings(
            live=live,
            kill_switch=kill_switch,
            approval_reference="approval:synthetic-cross-lane" if live else "",
        ),
        post=post,
    )


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_security_audit_lane4_receipt_fixture_verifies_full_canonical_receipt():
    bundle = _load_json(AUDIT_FIXTURE)
    receipt = _receipt_client().verify_receipt(
        bundle["event"], bundle["receipt"], expected_tenant="42"
    )
    assert receipt.event_id == bundle["event"]["event_id"]
    assert receipt.organization_id == "42"
    assert receipt.accepted_schema_version == "skills-audit/v1"
    assert receipt.durable is True


@pytest.mark.parametrize(
    ("mutation", "expected_tenant"),
    [
        ("signature", "42"),
        ("receipt_id", "42"),
        ("sink_partition", "42"),
        ("key_id", "42"),
        ("event_id", "42"),
        ("organization_id", "8"),
        ("accepted_schema_version", "42"),
        ("durable", "42"),
    ],
)
def test_receipt_tampering_and_binding_fail_closed(mutation, expected_tenant):
    bundle = _load_json(AUDIT_FIXTURE)
    changed = deepcopy(bundle["receipt"])
    if mutation == "signature":
        changed[mutation] = "ed25519:invalid"
    elif mutation == "durable":
        changed[mutation] = False
    elif mutation == "organization_id":
        changed[mutation] = "8"
    elif mutation == "accepted_schema_version":
        changed[mutation] = "policy-audit/v1"
    elif mutation == "event_id":
        changed[mutation] = "0" * 64
    elif mutation == "key_id":
        changed[mutation] = "unknown-key"
    else:
        changed[mutation] = f"changed-{changed[mutation]}"
    with pytest.raises(SkillsAuditReceiptError):
        _receipt_client().verify_receipt(
            bundle["event"], changed, expected_tenant=expected_tenant
        )


def test_receipt_rejects_event_tenant_mismatch_and_untrusted_key():
    bundle = _load_json(AUDIT_FIXTURE)
    event = {**bundle["event"], "organization_id": "8"}
    with pytest.raises(SkillsAuditReceiptError, match="tenant mismatch"):
        _receipt_client().verify_receipt(event, bundle["receipt"], expected_tenant="42")
    with pytest.raises(SkillsAuditReceiptError, match="not trusted"):
        _receipt_client(keys={}).verify_receipt(
            bundle["event"], bundle["receipt"], expected_tenant="42"
        )


def test_publisher_is_off_by_default_and_requires_verified_durable_receipt(tmp_path):
    bundle = _load_json(AUDIT_FIXTURE)
    token_file = tmp_path / "audit-token"
    token_file.write_text("synthetic-runtime-token", encoding="utf-8")

    def post(*_args, **_kwargs):
        return _Response(bundle["receipt"])

    disabled = _receipt_client(live=False, token_file=str(token_file), post=post)
    with pytest.raises(SkillsAuditReceiptError, match="disabled"):
        disabled.publish(bundle["event"], expected_tenant="42")

    enabled = _receipt_client(token_file=str(token_file), post=post)
    verified = enabled.publish(bundle["event"], expected_tenant="42")
    assert verified.receipt_id == bundle["receipt"]["receipt_id"]

    def tampered_post(*_args, **_kwargs):
        altered = {**bundle["receipt"], "sink_partition": "other-tenant"}
        return _Response(altered)

    tampered = _receipt_client(token_file=str(token_file), post=tampered_post)
    with pytest.raises(SkillsAuditReceiptError, match="signature verification failed"):
        tampered.publish(bundle["event"], expected_tenant="42")


class _Response:
    def __init__(self, value):
        self.value = value

    def raise_for_status(self):
        return None

    def json(self):
        return self.value


def test_lane2_iam_and_lane3_policy_regenerated_fixtures_match_current_contracts():
    identity = SkillsVerifiedIdentity.model_validate(
        _load_json(LANE_FIXTURES / "iam_verified_identity_v1.json")
    )
    policy = _load_json(LANE_FIXTURES / "policy_decision_v2.json")
    assert identity.schema_version == "skills.iam/v1"
    assert identity.tenant_id == "7"
    assert policy["schema_version"] == "policy-decision/v2"
    assert policy["error_code"].startswith("policy.")
    assert policy["tenant_id"] == "7"
