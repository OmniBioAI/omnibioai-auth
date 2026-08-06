"""PR12: iss/aud claims.

See app/core/jwt.py::_sign/decode_token docstrings for why `aud`
enforcement is delegated to jose (opportunistic: only enforced when the
claim is present) while `iss` is checked by hand the same way (jose's
`issuer` kwarg would otherwise *require* the claim once passed, rejecting
every pre-PR12/synthetic token outright).
"""

import pytest
from jose import jwt as jose_jwt
from jose.exceptions import JWTClaimsError

from app.core.config import settings
from app.core.jwt import create_access_token, create_refresh_token, decode_token


def test_access_token_carries_iss_and_aud():
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    claims = jose_jwt.get_unverified_claims(token)
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE


def test_refresh_token_carries_iss_and_aud():
    token = create_refresh_token({"sub": "1", "email": "a@omnibioai.test"})
    claims = jose_jwt.get_unverified_claims(token)
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE


def test_decode_token_accepts_valid_iss_and_aud():
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    claims = decode_token(token)
    assert claims["sub"] == "1"


def test_decode_token_rejects_wrong_audience():
    bad = jose_jwt.encode(
        {"sub": "1", "aud": "some-other-service", "exp": 9999999999},
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    with pytest.raises(JWTClaimsError):
        decode_token(bad)


def test_decode_token_rejects_wrong_issuer():
    bad = jose_jwt.encode(
        {"sub": "1", "iss": "some-other-service", "exp": 9999999999},
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    with pytest.raises(JWTClaimsError):
        decode_token(bad)


def test_decode_token_accepts_token_missing_aud_and_iss_entirely():
    """Migration-window requirement: a token minted before this change (or
    a hand-built test/synthetic token) has no `aud`/`iss` claims at all --
    must still decode, not be rejected outright."""
    legacy = jose_jwt.encode(
        {"sub": "1", "exp": 9999999999}, settings.SECRET_KEY, algorithm="HS256"
    )
    claims = decode_token(legacy)
    assert claims["sub"] == "1"
