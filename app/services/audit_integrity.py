"""Versioned per-record integrity for the Auth audit ledger.

Historical rows with all integrity columns NULL are reported as legacy,
not as verified. Version 1 signs a fixed, explicit set of immutable fields
using canonical UTF-8 JSON and HMAC-SHA-256.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

from app.core.config import settings

INTEGRITY_VERSION = 1
INTEGRITY_ALGORITHM = "HMAC-SHA-256"
_HEX_KEY = re.compile(r"\A[0-9a-fA-F]+\Z")
_SIGNED_FIELDS = (
    "event_type",
    "actor_user_id",
    "target_user_id",
    "organization_id",
    "resource_type",
    "resource_id",
    "before_state",
    "after_state",
    "event_metadata",
    "created_at",
)


class IntegrityResult(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    LEGACY_UNSIGNED = "legacy_unsigned"
    UNSUPPORTED_VERSION = "unsupported_version"


def _key_bytes(key_hex: str | None = None) -> bytes:
    candidate = settings.AUTH_AUDIT_INTEGRITY_KEY if key_hex is None else key_hex
    if not isinstance(candidate, str) or not _HEX_KEY.fullmatch(candidate):
        raise RuntimeError("Auth audit integrity key is missing or malformed")
    try:
        key = bytes.fromhex(candidate)
    except ValueError as exc:
        raise RuntimeError("Auth audit integrity key is malformed") from exc
    if len(key) < 32:
        raise RuntimeError("Auth audit integrity key must contain at least 256 bits")
    return key


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Non-finite values are not valid audit JSON")
        return value
    if isinstance(value, (datetime, date)):
        if isinstance(value, datetime):
            if value.tzinfo is not None:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            return value.isoformat(timespec="microseconds")
        return value.isoformat()
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("Audit JSON object keys must be strings")
        return {k: _normalize(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise ValueError(f"Unsupported audit integrity value type: {type(value).__name__}")


def canonical_record(record: Any) -> bytes:
    """Return deterministic UTF-8 JSON; every signed field is always present.

    Explicit nulls remain JSON null and empty strings/objects remain distinct.
    """
    body = {name: _normalize(getattr(record, name, None)) for name in _SIGNED_FIELDS}
    envelope = {"canonicalization": "omnibioai-auth-audit-v1", "record": body}
    return json.dumps(
        envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def sign_record(record: Any, key_hex: str | None = None) -> str:
    return hmac.new(_key_bytes(key_hex), canonical_record(record), hashlib.sha256).hexdigest()


def set_integrity(record: Any, key_hex: str | None = None) -> None:
    record.integrity_version = INTEGRITY_VERSION
    record.integrity_algorithm = INTEGRITY_ALGORITHM
    record.integrity_digest = sign_record(record, key_hex)


def verify_record(record: Any, key_hex: str | None = None) -> IntegrityResult:
    version = getattr(record, "integrity_version", None)
    algorithm = getattr(record, "integrity_algorithm", None)
    digest = getattr(record, "integrity_digest", None)
    if version is None and algorithm is None and digest is None:
        return IntegrityResult.LEGACY_UNSIGNED
    if version != INTEGRITY_VERSION or algorithm != INTEGRITY_ALGORITHM:
        return IntegrityResult.UNSUPPORTED_VERSION
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return IntegrityResult.INVALID
    expected = sign_record(record, key_hex)
    return IntegrityResult.VALID if hmac.compare_digest(expected, digest) else IntegrityResult.INVALID
