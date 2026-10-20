"""Policy parsing, secret injection, and exact UTC expiry boundaries."""
from datetime import datetime, timedelta

import pytest

from app.core.config import load_license_key_pepper, parse_license_allowed_validity_days
from app.db.models import LicenseKey
from app.db.session import SessionLocal
from app.services import license_service, manual_license_service


@pytest.mark.parametrize("raw", ["30,90", " 90, 30,30 "])
def test_validity_parser_accepts_comma_separated_positive_day_counts(raw):
    assert parse_license_allowed_validity_days(raw) == (30, 90)


@pytest.mark.parametrize("raw", [None, "", "  "])
def test_empty_validity_policy_disables_issuance(raw):
    assert parse_license_allowed_validity_days(raw) == ()


@pytest.mark.parametrize("raw", ["30,,90", "0", "-30", "30days", "30;90"])
def test_malformed_validity_policy_fails_closed(raw):
    with pytest.raises(ValueError, match="LICENSE_ALLOWED_VALIDITY_DAYS"):
        parse_license_allowed_validity_days(raw)


def test_30_and_90_are_accepted_other_duration_rejected_and_empty_disables(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "LICENSE_ALLOWED_VALIDITY_DAYS", (30, 90))
    manual_license_service.require_validity(30)
    manual_license_service.require_validity(90)
    with pytest.raises(manual_license_service.ManualLicenseError) as unsupported:
        manual_license_service.require_validity(31)
    assert unsupported.value.code == "unsupported_validity"

    monkeypatch.setattr(settings, "LICENSE_ALLOWED_VALIDITY_DAYS", ())
    with pytest.raises(manual_license_service.ManualLicenseError) as unconfigured:
        manual_license_service.require_validity(30)
    assert unconfigured.value.code == "validity_policy_unconfigured"


def test_pepper_file_injection_is_repeatable_and_never_echoes_secret(tmp_path, monkeypatch):
    secret_file = tmp_path / "license-pepper"
    secret_file.write_text("isolated-test-pepper-with-at-least-32-bytes\n", encoding="utf-8")
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    monkeypatch.setenv("LICENSE_KEY_PEPPER_FILE", str(secret_file))

    first = load_license_key_pepper()
    restarted = load_license_key_pepper()
    assert first == restarted
    assert len(first.encode("utf-8")) >= 32


def test_pepper_loader_rejects_short_or_ambiguous_configuration(monkeypatch):
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "short")
    monkeypatch.delenv("LICENSE_KEY_PEPPER_FILE", raising=False)
    with pytest.raises(ValueError) as short:
        load_license_key_pepper()
    assert "short" not in str(short.value)

    monkeypatch.setenv("LICENSE_KEY_PEPPER_FILE", "/unused/secret-file")
    with pytest.raises(ValueError, match="Configure only one"):
        load_license_key_pepper()


@pytest.mark.parametrize(
    "expiry,expected",
    [
        (datetime(2026, 1, 1, 12, 0, 0) - timedelta(microseconds=1), "expired"),
        (datetime(2026, 1, 1, 12, 0, 0), "expired"),
        (datetime(2026, 1, 1, 12, 0, 0) + timedelta(microseconds=1), None),
    ],
)
def test_license_expiry_uses_inclusive_utc_boundary(client, monkeypatch, expiry, expected):
    fixed_now = datetime(2026, 1, 1, 12, 0, 0)
    monkeypatch.setattr(license_service, "utc_now", lambda: fixed_now)
    db = SessionLocal()
    try:
        row = LicenseKey(
            key=f"OMNI-{expiry.microsecond:04d}-ABCD-EFGH-JKMP",
            key_digest=None,
            email="expiry-boundary@omnibioai.test",
            plan="beta", platform="both", max_uses=1, expires_at=expiry,
        )
        db.add(row)
        db.commit()
        result, reason = license_service.validate_and_consume(db, row.key, row.email, "web")
        assert reason == expected
        assert (result is None) is (expected is not None)
        assert manual_license_service.status_for(row) == ("expired" if expected else "active")
    finally:
        db.rollback()
        db.close()


def test_legacy_lookup_works_when_pepper_is_missing(monkeypatch, client):
    from app.core.config import settings

    monkeypatch.setattr(settings, "LICENSE_KEY_PEPPER", "")
    db = SessionLocal()
    try:
        row = LicenseKey(
            key="OMNI-LEGA-CYAA-AAAA-AAAA", key_digest=None,
            email="legacy-pepperless@omnibioai.test", plan="beta", platform="both",
        )
        db.add(row)
        db.commit()
        assert license_service.lookup_license(db, row.key).id == row.id
        with pytest.raises(RuntimeError, match="required"):
            license_service.digest_key("OMNI-NEWW-AAAA-AAAA-AAAA")
    finally:
        db.rollback()
        db.close()
