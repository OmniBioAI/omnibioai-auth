"""Hermetic coverage for authentication security helpers and provider edges."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import unquote

import pytest
from fastapi import HTTPException
from jose import jwt
from jose.exceptions import JWTClaimsError, JWTError

from app.api.deps import get_current_user, require_permission
from app.core import oauth_providers
from app.core.config import settings
from app.core.jwt import (
    create_access_token,
    create_link_token,
    create_mfa_challenge_token,
    create_oauth_state_token,
    create_saml_relay_state_token,
    create_saml_slo_relay_state_token,
    create_service_access_token,
    create_sso_state_token,
    decode_token,
)
from app.core.token_revocation import assert_token_usable, blacklist_access_token
from app.services.oauth_service import _code_challenge_s256, build_authorize_url
from app.services.org_oidc_service import SSOLoginError, _find_signing_key
from app.services.org_oidc_service import build_authorize_url as build_sso_authorize_url
from app.services.service_tokens import ServiceTokenIssuer


def test_access_token_round_trip_and_invalid_signature_are_rejected():
    token = create_access_token({"sub": "7", "email": "user@example.test"})
    claims = decode_token(token)
    assert claims["sub"] == "7"
    assert claims["type"] == "access"
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE

    parts = token.rsplit(".", 1)
    with pytest.raises(JWTError):
        decode_token(parts[0] + ".invalid-signature")


def test_decode_token_rejects_wrong_audience_and_issuer():
    wrong_aud = jwt.encode(
        {"sub": "7", "aud": "other", "iss": settings.JWT_ISSUER},
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    with pytest.raises(JWTError):
        decode_token(wrong_aud)

    wrong_issuer = jwt.encode(
        {"sub": "7", "aud": settings.JWT_AUDIENCE, "iss": "untrusted"},
        settings.SECRET_KEY,
        algorithm="HS256",
    )
    with pytest.raises(JWTClaimsError, match="Invalid issuer"):
        decode_token(wrong_issuer)


def test_oauth_state_token_contains_provider_and_optional_pkce_verifier():
    token = create_oauth_state_token("google", code_verifier="verifier")
    claims = decode_token(token)
    assert claims["type"] == "oauth_state"
    assert claims["provider"] == "google"
    assert claims["code_verifier"] == "verifier"

    legacy = decode_token(create_oauth_state_token("github"))
    assert "code_verifier" not in legacy


def test_specialized_tokens_have_distinct_types_and_bound_claims():
    tokens = [
        (create_sso_state_token(4, 5, "verifier", "nonce"), "sso_state"),
        (create_saml_relay_state_token(4, 6, "request-1"), "saml_relay_state"),
        (create_saml_slo_relay_state_token(4, 6, "request-2"), "saml_slo_relay_state"),
        (create_service_access_token({"service": "worker"}, 2), "access"),
        (create_mfa_challenge_token(7, "password", idp_org_id=8), "mfa_challenge"),
        (create_link_token(7, "google", "g-1", "user@example.test"), "oauth_link"),
    ]
    for token, token_type in tokens:
        assert decode_token(token)["type"] == token_type

    sso_claims = decode_token(tokens[0][0])
    assert sso_claims["organization_id"] == 4
    assert sso_claims["nonce"] == "nonce"
    mfa_claims = decode_token(tokens[4][0])
    assert mfa_claims["user_id"] == 7
    assert "sub" not in mfa_claims


def test_rs256_issuance_and_verification_uses_the_configured_algorithm(monkeypatch):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    token = create_access_token({"sub": "7"})
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    assert decode_token(token)["sub"] == "7"


def test_provider_configuration_and_userinfo_normalization_edges():
    with patch.dict(
        oauth_providers.PROVIDERS["google"],
        {"client_id": "id", "client_secret": "secret"},
    ):
        assert oauth_providers.is_configured("google") is True
    assert oauth_providers.is_configured("does-not-exist") is False
    assert oauth_providers.redirect_uri_for("google").endswith("/auth/google/callback")

    assert oauth_providers.parse_userinfo("google", {"sub": 12, "email": "g@example.test"}) == (
        "12",
        "g@example.test",
    )
    assert oauth_providers.parse_userinfo(
        "github",
        {"id": 9, "email": None},
        [{"email": "unverified@example.test", "verified": False, "primary": True},
         {"email": "verified@example.test", "verified": True, "primary": False}],
    ) == ("9", "verified@example.test")
    assert oauth_providers.parse_userinfo(
        "microsoft", {"sub": "m1", "preferred_username": "m@example.test"}
    ) == ("m1", "m@example.test")
    with pytest.raises(KeyError):
        oauth_providers.parse_userinfo("google", {})
    with pytest.raises(ValueError):
        oauth_providers.parse_userinfo("unknown", {})


def test_pkce_and_authorize_urls_include_security_parameters():
    verifier = "a" * 43
    challenge = _code_challenge_s256(verifier)
    assert len(challenge) > 40

    with patch.dict(
        oauth_providers.PROVIDERS["google"],
        {"client_id": "client", "client_secret": "secret"},
    ):
        url = build_authorize_url("google")
    assert "code_challenge=" in url
    assert "code_challenge_method=S256" in url
    assert "redirect_uri=" in url


def test_oidc_key_selection_and_authorize_url_fail_closed():
    assert _find_signing_key({"keys": [{"kid": "k1"}]}, "k1")["kid"] == "k1"
    assert _find_signing_key({"keys": [{"kid": "only"}]}, None)["kid"] == "only"
    with pytest.raises(SSOLoginError, match="does not match"):
        _find_signing_key({"keys": [{"kid": "k1"}]}, "missing")
    with pytest.raises(SSOLoginError, match="determine"):
        _find_signing_key({"keys": [{"kid": "a"}, {"kid": "b"}]}, None)

    config = SimpleNamespace(client_id="client", authorization_endpoint="https://idp/authorize")
    url = build_sso_authorize_url(config, "acme", "state", "challenge", "nonce")
    assert "client_id=client" in url
    assert "nonce=nonce" in url
    assert "/auth/sso/acme/callback" in unquote(url)


def test_service_tokens_are_short_lived_and_audienced():
    token = ServiceTokenIssuer("secret").issue_token("worker", ["api"], ttl_seconds=30)
    claims = jwt.decode(token, "secret", algorithms=["HS256"], audience="api")
    assert claims["type"] == "service"
    assert claims["service"] == "worker"
    assert claims["aud"] == ["api"]
    assert claims["exp"] - claims["iat"] == 30


def test_auth_dependency_fails_closed_and_permission_wrapper_checks_claims():
    with pytest.raises(HTTPException) as exc:
        get_current_user(SimpleNamespace(credentials="bad-token"))
    assert exc.value.status_code == 401

    dependency = require_permission("dataset:read")
    assert dependency(user={"permissions": ["dataset:read"]})["permissions"] == ["dataset:read"]
    with pytest.raises(HTTPException) as denied:
        dependency(user={"permissions": []})
    assert denied.value.status_code == 403


def test_blacklist_access_token_uses_remaining_ttl_and_fails_open():
    token = create_access_token({"sub": "7"})
    with patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist_access_token(token)
    args = blacklist.setex.call_args.args
    assert args[0].startswith("blacklist:jti:")
    assert args[1] >= 1
    assert args[2] == "1"

    with patch("app.core.token_revocation.decode_token", side_effect=ValueError("bad")), \
         patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist_access_token("malformed")
        blacklist.setex.assert_not_called()


def test_assert_token_usable_handles_redis_failure_and_revoked_or_inactive_users():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    with patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist.exists.side_effect = ConnectionError("redis down")
        assert_token_usable({"sub": None, "jti": "j1"}, db)

    with patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist.exists.return_value = True
        with pytest.raises(HTTPException, match="Token revoked"):
            assert_token_usable({"jti": "j1"}, db)

    db.query.return_value.filter.return_value.first.return_value = object()
    with patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist.exists.return_value = False
        with pytest.raises(HTTPException, match="Token revoked"):
            assert_token_usable({"jti": "j1", "sub": "7"}, db)

    db.query.return_value.filter.return_value.first.side_effect = [
        None,
        SimpleNamespace(status="disabled"),
    ]
    with patch("app.core.token_revocation._blacklist") as blacklist:
        blacklist.exists.return_value = False
        with pytest.raises(HTTPException, match="User inactive"):
            assert_token_usable({"sub": "7"}, db)
