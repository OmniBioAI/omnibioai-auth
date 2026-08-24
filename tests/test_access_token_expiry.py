"""create_access_token()'s real exp claim must track
settings.ACCESS_TOKEN_EXPIRE_MINUTES, not a hardcoded literal.

Found during review of PR #62 (first-party SSO): /oauth/token/
authorization-code's expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES*60
(app/api/routes_oauth_token.py) was the only place in the codebase that
ever read this setting -- create_access_token() itself still hardcoded
`timedelta(minutes=15)`, so the two could silently drift apart the moment
an operator changed the setting away from its own default (15, which is
exactly why the drift went undetected: 15 == 15).
"""

from datetime import datetime, timedelta

from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.jwt import create_access_token


def test_access_token_exp_matches_configured_expiry_minutes(monkeypatch):
    monkeypatch.setattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 42)

    before = datetime.utcnow()
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    after = datetime.utcnow()

    claims = jose_jwt.get_unverified_claims(token)
    exp = datetime.utcfromtimestamp(claims["exp"])

    # exp must fall within [before + 42min, after + 42min] -- not exactly
    # equal to a single computed instant, since create_access_token() runs
    # its own datetime.utcnow() a moment after `before` was captured here.
    # A 1-second tolerance on the lower bound absorbs jose's own exp claim
    # being an integer Unix timestamp (truncated, not rounded, to whole
    # seconds) -- `before` itself still carries microseconds.
    assert before + timedelta(minutes=42, seconds=-1) <= exp <= after + timedelta(minutes=42)
    # And explicitly NOT the old hardcoded 15-minute value -- the real
    # regression this test guards against.
    assert not (before + timedelta(minutes=15, seconds=-1) <= exp <= after + timedelta(minutes=15))


def test_access_token_exp_matches_default_fifteen_minutes():
    """Sanity check the other direction: the untouched default (15) still
    produces a real ~15-minute token, so this fix didn't just make the
    setting readable without actually wiring it into the real value."""
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 15  # the actual default, not assumed

    before = datetime.utcnow()
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    after = datetime.utcnow()

    claims = jose_jwt.get_unverified_claims(token)
    exp = datetime.utcfromtimestamp(claims["exp"])

    assert before + timedelta(minutes=15, seconds=-1) <= exp <= after + timedelta(minutes=15)
