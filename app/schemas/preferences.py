"""Typed personal preferences. None means use the current device's time zone."""
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, field_validator


class PreferencesOut(BaseModel):
    timezone: str | None = None


class PreferencesPatch(PreferencesOut):
    model_config = ConfigDict(extra="forbid")

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value):
        if value is None:
            return value
        # Reject abbreviations (CST/EST/IST), file paths and legacy POSIX rules.
        if len(value) > 100 or value.startswith(("posix/", "right/")) or (value != "UTC" and "/" not in value):
            raise ValueError("Use an IANA time zone or UTC")
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("Use an IANA time zone or UTC") from None
        return value
