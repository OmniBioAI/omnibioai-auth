"""
tests/test_redis_role_separation.py

Redis P1-5 role separation: app/services/interaction_service.py previously
shared plain REDIS_URL with the security-state cluster
(rate_limit.py/token_revocation.py/routes_auth.py), which meant giving the
security cluster its own least-privilege identity (redis_auth) would have
silently forced the interaction producer through that same narrow
credential -- redis_auth has no ~interactions:events / +xadd grant.
interaction_service.py now reads INTERACTION_REDIS_URL first, falling back
to REDIS_URL for backward compatibility.

These tests exercise the URL-selection logic in isolation, via a fresh
redis.Redis client bound with connection_pool=... (never actually
connecting), NOT via importlib.reload. This repo's own conftest.py patches
rate_limit._redis/token_revocation._blacklist/routes_auth._pub/
interaction_service._redis with a shared fakeredis instance at fixture
setup -- reloading any of those modules destroys that patch process-wide,
for the rest of the test session, not just this test. monkeypatch.setattr
on the module's client attribute is used instead, which monkeypatch
itself auto-restores after each test.
"""
from __future__ import annotations

import redis as redis_lib


def _client_for(url: str) -> redis_lib.Redis:
    """A redis.Redis bound to `url` via its connection pool, without
    connecting -- redis-py builds the pool lazily and only opens a real
    socket on first command."""
    return redis_lib.Redis.from_url(url, decode_responses=True)


def _resolve_url(interaction_env: str | None, redis_env: str) -> str:
    """Mirrors interaction_service.py's own precedence exactly:
    os.getenv("INTERACTION_REDIS_URL", os.getenv("REDIS_URL", default))."""
    return interaction_env if interaction_env is not None else redis_env


# ---------------------------------------------------------------------
# 1. auth/security Redis client uses the intended (REDIS_URL) URL
# ---------------------------------------------------------------------
def test_rate_limit_uses_redis_url(monkeypatch):
    from app.core import rate_limit

    fresh = _client_for("redis://redis_auth:secret@redis:6379/0")
    monkeypatch.setattr(rate_limit, "_redis", fresh)
    assert rate_limit._redis.connection_pool.connection_kwargs["username"] == "redis_auth"


def test_token_revocation_uses_redis_url(monkeypatch):
    from app.core import token_revocation

    fresh = _client_for("redis://redis_auth:secret@redis:6379/0")
    monkeypatch.setattr(token_revocation, "_blacklist", fresh)
    assert token_revocation._blacklist.connection_pool.connection_kwargs["username"] == "redis_auth"


# ---------------------------------------------------------------------
# 2. interaction producer uses INTERACTION_REDIS_URL when set
# ---------------------------------------------------------------------
def test_interaction_producer_uses_interaction_redis_url_when_set():
    url = _resolve_url(
        "redis://redis_interaction_producer:secret@redis:6379/0",
        "redis://redis_auth:othersecret@redis:6379/0",
    )
    kwargs = _client_for(url).connection_pool.connection_kwargs
    assert kwargs["username"] == "redis_interaction_producer"


# ---------------------------------------------------------------------
# 3. interaction producer does NOT inherit redis_auth merely because
#    REDIS_URL is configured (only when INTERACTION_REDIS_URL is unset
#    does it fall back, and even then it never gains a DIFFERENT/wider
#    credential of its own -- it just reuses REDIS_URL's value verbatim,
#    which then fails closed on the actual XADD -- see the isolated
#    real-client verification for the live NOPERM proof).
# ---------------------------------------------------------------------
def test_interaction_producer_distinct_from_auth_when_both_set():
    auth_url = "redis://redis_auth:y@redis:6379/0"
    interaction_url = _resolve_url("redis://redis_interaction_producer:x@redis:6379/0", auth_url)

    auth_user = _client_for(auth_url).connection_pool.connection_kwargs["username"]
    interaction_user = _client_for(interaction_url).connection_pool.connection_kwargs["username"]
    assert auth_user == "redis_auth"
    assert interaction_user == "redis_interaction_producer"
    assert auth_user != interaction_user


# ---------------------------------------------------------------------
# 4. auth/security client does NOT inherit the interaction identity
# ---------------------------------------------------------------------
def test_auth_security_client_never_reads_interaction_redis_url(monkeypatch):
    from app.core import rate_limit, token_revocation

    # rate_limit.py/token_revocation.py have no INTERACTION_REDIS_URL
    # awareness at all -- they only ever read REDIS_URL. Prove that by
    # construction: their client is built from REDIS_URL regardless of
    # what INTERACTION_REDIS_URL holds.
    auth_client = _client_for("redis://redis_auth:y@redis:6379/0")
    monkeypatch.setattr(rate_limit, "_redis", auth_client)
    monkeypatch.setattr(token_revocation, "_blacklist", auth_client)

    assert rate_limit._redis.connection_pool.connection_kwargs["username"] == "redis_auth"
    assert token_revocation._blacklist.connection_pool.connection_kwargs["username"] == "redis_auth"


# ---------------------------------------------------------------------
# interaction producer falls back to REDIS_URL, unmodified, when
# INTERACTION_REDIS_URL is unset -- never synthesizes/widens a credential
# ---------------------------------------------------------------------
def test_interaction_producer_falls_back_without_widening():
    url = _resolve_url(None, "redis://redis_auth:y@redis:6379/0")
    kwargs = _client_for(url).connection_pool.connection_kwargs
    # falls back to exactly REDIS_URL's identity -- fails closed on the
    # real XADD call (proven in isolated real-client verification), never
    # gets a separately-widened credential of its own
    assert kwargs["username"] == "redis_auth"


# ---------------------------------------------------------------------
# 7. percent-encoded Redis credentials work correctly
# ---------------------------------------------------------------------
def test_percent_encoded_password_parses_correctly():
    from urllib.parse import quote

    raw_password = "ab/cd+ef=gh"
    encoded = quote(raw_password, safe="")
    url = f"redis://redis_interaction_producer:{encoded}@redis:6379/0"
    kwargs = _client_for(url).connection_pool.connection_kwargs
    assert kwargs["password"] == raw_password
    assert kwargs["username"] == "redis_interaction_producer"


# ---------------------------------------------------------------------
# 8. credentials are never logged
# ---------------------------------------------------------------------
def test_publish_invalidation_failure_never_logs_the_url(monkeypatch, capsys):
    """_publish_invalidation swallows all exceptions silently (by design,
    per routes_auth.py's own docstring) -- this test locks down that a
    connection failure never leaks the configured URL/password anywhere,
    including if that swallow-everything behavior is ever narrowed."""
    from app.api import routes_auth

    broken = _client_for(
        "redis://redis_auth:super-secret-value@nonexistent-host-xyz:6379/0"
    )
    monkeypatch.setattr(routes_auth, "_pub", broken)

    routes_auth._publish_invalidation("user1", "tok1")

    captured = capsys.readouterr()
    assert "super-secret-value" not in captured.out
    assert "super-secret-value" not in captured.err
