"""Hermetic security-boundary tests for JWT decoding and RBAC dependencies.

These cases exercise the failure branches that route-level tests can miss:
malformed headers, expiry, algorithm confusion, and the two service-token
authorization outcomes.  No database, network, or live identity provider is
needed.

Developer: Manish Kumar <manish@omnibioai.org>
"""

import time

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.jwt import decode_token
from app.rbac import require_service_identity, require_service_scope


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    """Wrap a token string as Bearer HTTPAuthorizationCredentials."""
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_decode_token_rejects_malformed_token_without_header():
    """decode_token raises for a string that is not a JWT."""
    with pytest.raises(Exception):
        decode_token("not-a-jwt")


def test_decode_token_rejects_expired_token():
    """decode_token raises for a correctly signed token whose exp is already in the past."""
    expired = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) - 1},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(Exception):
        decode_token(expired)


def test_decode_token_rejects_algorithm_confusion_token():
    """decode_token raises for a token signed with HS384 rather than the configured algorithm."""
    token = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) + 60},
        settings.SECRET_KEY,
        algorithm="HS384",
    )

    with pytest.raises(Exception):
        decode_token(token)


def test_require_service_scope_rejects_invalid_token():
    """The service-scope dependency rejects an invalid token with 401."""
    dependency = require_service_scope("read:catalog")

    with pytest.raises(HTTPException) as exc:
        dependency(token=_credentials("not-a-jwt"))

    assert exc.value.status_code == 401


def test_require_service_scope_rejects_missing_scope():
    """The service-scope dependency rejects a client-credentials token lacking the required scope
    with 403.
    """
    token = jose_jwt.encode(
        {
            "auth_method": "client_credentials",
            "scopes": ["read:other"],
            "exp": int(time.time()) + 60,
        },
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(HTTPException) as exc:
        require_service_scope("read:catalog")(token=_credentials(token))

    assert exc.value.status_code == 403


def test_require_service_identity_rejects_user_token():
    """The service-identity dependency rejects a user token that is not a client-credentials service
    token with 403.
    """
    token = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) + 60},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(HTTPException) as exc:
        require_service_identity()(token=_credentials(token))

    assert exc.value.status_code == 403
