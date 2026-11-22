"""/auth/validate: "not valid" (200, valid=false) vs "cannot tell right now" (503).

When the revocation state in Redis or the database cannot be read, the
endpoint answers 503 with {"valid": false, "error": "authentication_state_unavailable"}
instead of a plain {"valid": false}. The body still says valid=false, so
callers that only read the body keep refusing the token as before.
"""

from unittest.mock import patch

import redis
from sqlalchemy.exc import OperationalError

from app.core import token_revocation

UNAVAILABLE = {"valid": False, "error": "authentication_state_unavailable"}


def test_redis_unavailable_is_503(client, auth_tokens):
    exists = token_revocation._blacklist.exists
    previous = exists.side_effect
    exists.side_effect = redis.ConnectionError("redis down")
    try:
        resp = client.post("/auth/validate", json={"token": auth_tokens["access_token"]})
    finally:
        exists.side_effect = previous
    assert resp.status_code == 503
    assert resp.json() == UNAVAILABLE
    assert resp.headers["Retry-After"] == "2"
    assert resp.headers["Cache-Control"] == "no-store"


def test_database_error_is_503(client, auth_tokens):
    with patch("app.api.routes_auth.assert_token_usable",
               side_effect=OperationalError("SELECT 1", {}, Exception("db down"))):
        resp = client.post("/auth/validate", json={"token": auth_tokens["access_token"]})
    assert resp.status_code == 503
    assert resp.json() == UNAVAILABLE


def test_revoked_token_is_still_200_valid_false(client, auth_tokens):
    token = auth_tokens["access_token"]
    assert client.post("/auth/logout", json={"refresh_token": auth_tokens["refresh_token"],
                                             "access_token": token}).status_code == 200
    resp = client.post("/auth/validate", json={"token": token})
    assert resp.status_code == 200
    assert resp.json() == {"valid": False}


def test_malformed_token_is_still_200_valid_false(client):
    resp = client.post("/auth/validate", json={"token": "not.a.valid.token"})
    assert resp.status_code == 200
    assert resp.json() == {"valid": False}


def test_valid_token_unchanged(client, auth_tokens):
    resp = client.post("/auth/validate", json={"token": auth_tokens["access_token"]})
    assert resp.status_code == 200
    assert resp.json()["valid"] is True
