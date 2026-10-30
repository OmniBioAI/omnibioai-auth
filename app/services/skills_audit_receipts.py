"""Fail-closed Security Audit client for Skills durable receipts (B-06/B-07)."""

from __future__ import annotations

import base64
import json
import os
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


RECEIPT_DOMAIN = b"omnibioai-security-audit-receipt-v1\x00"
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def canonical_json(value: Any) -> bytes:
    """Match Security Audit's canonical JSON encoding byte for byte."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class SkillsAuditReceiptError(RuntimeError):
    """Receipt transport, schema, binding, or signature verification failed."""


class DurableSkillsAuditReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    accepted_schema_version: str = Field(pattern=r"^(skills-audit|policy-audit)/v1$")
    durable: bool
    durable_at: datetime
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    key_id: str = Field(min_length=1, max_length=64)
    organization_id: str = Field(pattern=r"^[0-9]{1,255}$")
    receipt_id: str = Field(min_length=8, max_length=256)
    signature: str = Field(min_length=16, max_length=256)
    sink_partition: str = Field(min_length=1, max_length=256)

    @field_validator("durable_at", mode="before")
    @classmethod
    def parse_timestamp(cls, value: Any) -> datetime:
        # JSON receipts carry RFC 3339 strings; strict model validation still
        # applies to every other field.
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("durable_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("durable_at must include a timezone")
        return value

    def signed_fields(self) -> dict[str, Any]:
        """Every receipt field is signed except the signature itself."""
        return self.model_dump(mode="json", exclude={"signature"})


class SkillsAuditReceiptSettings:
    """Default-off transport settings; keys and endpoints are runtime injected."""

    def __init__(self, *, live: bool, kill_switch: bool, approval_reference: str):
        self.live = live
        self.kill_switch = kill_switch
        self.approval_reference = approval_reference

    @classmethod
    def from_env(cls) -> SkillsAuditReceiptSettings:
        return cls(
            live=os.getenv("SKILLS_SECURITY_AUDIT_LIVE", "false").lower() == "true",
            kill_switch=os.getenv("SKILLS_SECURITY_AUDIT_KILL_SWITCH", "true").lower() == "true",
            approval_reference=os.getenv("SKILLS_SECURITY_AUDIT_APPROVAL_REF", "").strip(),
        )

    def require_enabled(self) -> None:
        if self.kill_switch:
            raise SkillsAuditReceiptError("security-audit kill switch is active")
        if not self.live or not self.approval_reference:
            raise SkillsAuditReceiptError("security-audit receipt client is disabled")


class SecurityAuditReceiptClient:
    """Publish events and accept only a matching, durable, signed receipt.

    ``verification_keys`` is an injected key-ID to raw Ed25519 public-key
    map obtained from the approved runtime trust configuration. The client
    has no compiled endpoint, token, or production public key.
    """

    def __init__(
        self,
        *,
        url: str,
        token_file: str,
        verification_keys: Mapping[str, bytes],
        settings: SkillsAuditReceiptSettings | None = None,
        post: Callable[..., Any] | None = None,
    ) -> None:
        self._url = url
        self._token_file = token_file
        self._keys = dict(verification_keys)
        self._settings = settings or SkillsAuditReceiptSettings.from_env()
        self._post = post or httpx.post

    @staticmethod
    def _decode_signature(signature: str) -> bytes:
        scheme, separator, encoded = signature.partition(":")
        if not separator or scheme != "ed25519" or not encoded:
            raise SkillsAuditReceiptError("security-audit receipt signature format is invalid")
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, base64.binascii.Error) as exc:
            raise SkillsAuditReceiptError("security-audit receipt signature encoding is invalid") from exc
        if len(raw) != 64:
            raise SkillsAuditReceiptError("security-audit receipt signature length is invalid")
        return raw

    def verify_receipt(
        self,
        event: Mapping[str, Any],
        receipt_value: Mapping[str, Any],
        *,
        expected_tenant: str,
    ) -> DurableSkillsAuditReceipt:
        """Validate schema, exact event/tenant binding, durability and signature."""
        try:
            if not isinstance(expected_tenant, str) or not re.fullmatch(r"[0-9]{1,255}", expected_tenant):
                raise SkillsAuditReceiptError("expected tenant must be an opaque decimal string")
            receipt = DurableSkillsAuditReceipt.model_validate(dict(receipt_value))
            if receipt.durable is not True:
                raise SkillsAuditReceiptError("security-audit receipt is not durable")
            if receipt.event_id != event.get("event_id"):
                raise SkillsAuditReceiptError("security-audit receipt event ID mismatch")
            if receipt.organization_id != expected_tenant or event.get("organization_id") != expected_tenant:
                raise SkillsAuditReceiptError("security-audit receipt tenant mismatch")
            event_schema = event.get("schema_version")
            if event_schema != receipt.accepted_schema_version:
                raise SkillsAuditReceiptError("security-audit receipt schema version mismatch")
            if not _KEY_ID.fullmatch(receipt.key_id):
                raise SkillsAuditReceiptError("security-audit receipt key ID is invalid")
            public_key = self._keys.get(receipt.key_id)
            if not isinstance(public_key, bytes) or len(public_key) != 32:
                raise SkillsAuditReceiptError("security-audit receipt signing key is not trusted")
            signature = self._decode_signature(receipt.signature)
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(
                    signature,
                    RECEIPT_DOMAIN + canonical_json(receipt.signed_fields()),
                )
            except (InvalidSignature, ValueError) as exc:
                raise SkillsAuditReceiptError("security-audit receipt signature verification failed") from exc
            return receipt
        except SkillsAuditReceiptError:
            raise
        except (ValidationError, TypeError, ValueError, KeyError) as exc:
            raise SkillsAuditReceiptError("security-audit receipt is malformed") from exc
        except Exception as exc:
            raise SkillsAuditReceiptError("security-audit receipt verification unavailable") from exc

    def publish(self, event: Mapping[str, Any], *, expected_tenant: str) -> DurableSkillsAuditReceipt:
        """Send an event and fail closed unless its full signed receipt verifies."""
        self._settings.require_enabled()
        if not self._url or not self._token_file:
            raise SkillsAuditReceiptError("security-audit publisher is not configured")
        try:
            token = Path(self._token_file).read_text(encoding="utf-8").strip()
            if not token:
                raise SkillsAuditReceiptError("security-audit workload token is absent")
            response = self._post(
                self._url,
                json=dict(event),
                headers={"Authorization": f"Bearer {token}"},
                timeout=httpx.Timeout(1.5, connect=0.25),
            )
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise SkillsAuditReceiptError("security-audit receipt response is malformed")
            return self.verify_receipt(event, value, expected_tenant=expected_tenant)
        except SkillsAuditReceiptError:
            raise
        except Exception as exc:
            raise SkillsAuditReceiptError("security-audit receipt could not be confirmed") from exc
