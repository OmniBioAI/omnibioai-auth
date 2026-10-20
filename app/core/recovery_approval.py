"""Verification for offline, Platform-Owner-signed credential recovery approvals.

The private signing key stays with the out-of-band approval authority. This
runtime contains only the pinned public key from a read-only secret mount.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

APPROVAL_PUBLIC_KEY_PATH = "/run/secrets/auth-recovery-approval-public-key.pem"
MAX_APPROVAL_BYTES = 16 * 1024
MAX_APPROVAL_LIFETIME = timedelta(minutes=30)
APPROVAL_FIELDS = frozenset({
    "version", "approval_id", "action", "target_user_id", "target_email",
    "expected_credential_state", "operator_login", "approver_user_id",
    "ticket_id", "identity_verification_ref", "allow_mfa_reset",
    "issued_at", "expires_at",
})


class RecoveryApprovalError(ValueError):
    """Safe-to-display approval validation failure; contains no secret data."""


@dataclass(frozen=True)
class RecoveryApproval:
    approval_id: str
    action: str
    target_user_id: int
    target_email: str
    expected_credential_state: str
    operator_login: str
    approver_user_id: int
    ticket_id: str
    identity_verification_ref: str
    allow_mfa_reset: bool
    issued_at: datetime
    expires_at: datetime


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise RecoveryApprovalError(f"Invalid approval {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RecoveryApprovalError(f"Invalid approval {field}") from None
    if parsed.tzinfo is None:
        raise RecoveryApprovalError(f"Invalid approval {field}")
    return parsed.astimezone(timezone.utc)


def load_signed_recovery_approval(path: str | os.PathLike[str]) -> RecoveryApproval:
    """Read and validate one Ed25519-signed approval from a local file."""
    approval_path = Path(path)
    try:
        if approval_path.is_symlink():
            raise RecoveryApprovalError("Approval file must not be a symbolic link")
        file_stat = approval_path.stat()
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_APPROVAL_BYTES:
            raise RecoveryApprovalError("Approval file is not a valid regular file")
        raw = approval_path.read_bytes()
        public_key_path = Path(APPROVAL_PUBLIC_KEY_PATH)
        if public_key_path.is_symlink():
            raise RecoveryApprovalError("Trusted public key must not be a symbolic link")
        key_stat = public_key_path.stat()
        if (
            not stat.S_ISREG(key_stat.st_mode)
            or key_stat.st_uid != 0
            or key_stat.st_mode & 0o022
            or key_stat.st_size > 16 * 1024
        ):
            raise RecoveryApprovalError("Trusted public key is not protected")
        with open(public_key_path, "rb") as key_file:
            public_key_bytes = key_file.read(16 * 1024)
    except RecoveryApprovalError:
        raise
    except OSError:
        raise RecoveryApprovalError("Approval or trusted public key is unavailable") from None

    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RecoveryApprovalError("Approval file is invalid") from None
    if not isinstance(payload, dict) or set(payload) != APPROVAL_FIELDS | {"signature"}:
        raise RecoveryApprovalError("Approval file fields are invalid")
    signature_text = payload.pop("signature")
    if not isinstance(signature_text, str):
        raise RecoveryApprovalError("Approval signature is invalid")

    try:
        signature = base64.b64decode(signature_text, validate=True)
        public_key = load_pem_public_key(public_key_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Wrong key type")
        signed_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        public_key.verify(signature, signed_bytes)
    except Exception:
        raise RecoveryApprovalError("Approval signature is invalid") from None

    now = datetime.now(timezone.utc)
    issued_at = _parse_time(payload.get("issued_at"), "issued_at")
    expires_at = _parse_time(payload.get("expires_at"), "expires_at")
    if issued_at > now + timedelta(seconds=60) or expires_at <= now:
        raise RecoveryApprovalError("Approval is not currently valid")
    if expires_at <= issued_at or expires_at - issued_at > MAX_APPROVAL_LIFETIME:
        raise RecoveryApprovalError("Approval lifetime is invalid")

    try:
        approval_id = str(uuid.UUID(str(payload["approval_id"])))
    except (ValueError, TypeError, KeyError):
        raise RecoveryApprovalError("Approval identifier is invalid") from None
    if (
        type(payload.get("version")) is not int
        or payload.get("version") != 1
        or payload.get("action") not in {"admin_credential_recovery", "admin_mfa_recovery"}
    ):
        raise RecoveryApprovalError("Approval action is invalid")
    expected_states = {
        "admin_credential_recovery": "disabled_or_unsupported",
        "admin_mfa_recovery": "unknown_authenticator_enrollment",
    }
    if payload.get("expected_credential_state") != expected_states[payload["action"]]:
        raise RecoveryApprovalError("Approval credential state is invalid")
    if payload["action"] == "admin_mfa_recovery" and payload.get("allow_mfa_reset") is not True:
        raise RecoveryApprovalError("Approval MFA scope is invalid")
    if type(payload.get("target_user_id")) is not int or payload["target_user_id"] < 1:
        raise RecoveryApprovalError("Approval target is invalid")
    if type(payload.get("approver_user_id")) is not int or payload["approver_user_id"] < 1:
        raise RecoveryApprovalError("Approval authorizer is invalid")
    for field in ("target_email", "operator_login", "ticket_id", "identity_verification_ref"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 255:
            raise RecoveryApprovalError(f"Approval {field} is invalid")
    if not isinstance(payload.get("allow_mfa_reset"), bool):
        raise RecoveryApprovalError("Approval MFA scope is invalid")

    return RecoveryApproval(
        approval_id=approval_id,
        action=payload["action"],
        target_user_id=payload["target_user_id"],
        target_email=payload["target_email"],
        expected_credential_state=payload["expected_credential_state"],
        operator_login=payload["operator_login"],
        approver_user_id=payload["approver_user_id"],
        ticket_id=payload["ticket_id"],
        identity_verification_ref=payload["identity_verification_ref"],
        allow_mfa_reset=payload["allow_mfa_reset"],
        issued_at=issued_at,
        expires_at=expires_at,
    )
