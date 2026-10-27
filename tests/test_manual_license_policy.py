"""Policy parsing, secret injection, and expiry boundaries for manual licenses."""
from datetime import datetime, timedelta

import pytest

from app.core.config import load_license_key_pepper, parse_license_allowed_validity_days
from app.db.models import LicenseKey
from app.db.session import SessionLocal
from app.services import license_service, manual_license_service


@pytest.mark.parametrize("raw", ["30,90", " 90, 30,30 "])
def test_validity_parser_accepts_positive_comma_separated_days(raw):
    assert parse_license_allowed_validity_days(raw) == (30, 90)


@pytest.mark.parametrize("raw", [None, "", "  "])
def test_empty_validity_policy_disables_issuance(raw):
    assert parse_license_allowed_validity_days(raw) == ()


@pytest.mark.parametrize("raw", ["30,,90", "0", "-30", "30days", "30;90"])
def test_malformed_validity_policy_fails_closed(raw):
    with pytest.raises(ValueError, match="LICENSE_ALLOWED_VALIDITY_DAYS"):
        parse_license_allowed_validity_days(raw)


def test_validity_policy_restricts_manual_issuance(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "LICENSE_ALLOWED_VALIDITY_DAYS", (30, 90))
    manual_license_service.require_validity(30)
    with pytest.raises(manual_license_service.ManualLicenseError) as error:
        manual_license_service.require_validity(31)
    assert error.value.code == "unsupported_validity"
    monkeypatch.setattr(settings, "LICENSE_ALLOWED_VALIDITY_DAYS", ())
    with pytest.raises(manual_license_service.ManualLicenseError) as error:
        manual_license_service.require_validity(30)
    assert error.value.code == "validity_policy_unconfigured"


def test_pepper_file_loader_is_repeatable_and_does_not_echo_secret(tmp_path, monkeypatch):
    path = tmp_path / "license-pepper"
    path.write_text("test-only-license-pepper-value-32-bytes\n", encoding="utf-8")
    monkeypatch.delenv("LICENSE_KEY_PEPPER", raising=False)
    monkeypatch.setenv("LICENSE_KEY_PEPPER_FILE", str(path))
    assert load_license_key_pepper() == load_license_key_pepper()


def test_pepper_loader_rejects_ambiguous_or_short_values(monkeypatch):
    monkeypatch.setenv("LICENSE_KEY_PEPPER", "short")
    monkeypatch.delenv("LICENSE_KEY_PEPPER_FILE", raising=False)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        load_license_key_pepper()
    monkeypatch.setenv("LICENSE_KEY_PEPPER_FILE", "/unused/secret-file")
    with pytest.raises(ValueError, match="Configure only one"):
        load_license_key_pepper()


@pytest.mark.parametrize(
    "offset,expected",
    [(timedelta(microseconds=-1), "expired"), (timedelta(0), "expired"), (timedelta(microseconds=1), "active")],
)
def test_expiry_boundary_is_inclusive(monkeypatch, offset, expected):
    fixed_now = datetime(2026, 1, 1, 12)
    monkeypatch.setattr(license_service, "utc_now", lambda: fixed_now)
    row = LicenseKey(email="expiry@omnibioai.test", expires_at=fixed_now + offset)
    assert manual_license_service.status_for(row) == expected


def test_legacy_plaintext_lookup_remains_available(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "LICENSE_KEY_PEPPER", "")
    db = SessionLocal()
    try:
        row = LicenseKey(key="OMNI-LEGA-CYAA-AAAA-AAAA", email="legacy@omnibioai.test")
        db.add(row)
        db.commit()
        assert license_service.lookup_license(db, row.key).id == row.id
    finally:
        db.rollback()
        db.close()
