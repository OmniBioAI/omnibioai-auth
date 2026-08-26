"""Hermetic security-boundary tests for JWT decoding and RBAC dependencies.

These cases exercise the failure branches that route-level tests can miss:
malformed headers, expiry, algorithm confusion, and the two service-token
authorization outcomes.  No database, network, or live identity provider is
needed.
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
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_decode_token_rejects_malformed_token_without_header():
    with pytest.raises(Exception):
        decode_token("not-a-jwt")


def test_decode_token_rejects_expired_token():
    expired = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) - 1},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(Exception):
        decode_token(expired)


def test_decode_token_rejects_algorithm_confusion_token():
    token = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) + 60},
        settings.SECRET_KEY,
        algorithm="HS384",
    )

    with pytest.raises(Exception):
        decode_token(token)


def test_require_service_scope_rejects_invalid_token():
    dependency = require_service_scope("read:catalog")

    with pytest.raises(HTTPException) as exc:
        dependency(token=_credentials("not-a-jwt"))

    assert exc.value.status_code == 401


def test_require_service_scope_rejects_missing_scope():
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
    token = jose_jwt.encode(
        {"sub": "1", "exp": int(time.time()) + 60},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    with pytest.raises(HTTPException) as exc:
        require_service_identity()(token=_credentials(token))

    assert exc.value.status_code == 403
