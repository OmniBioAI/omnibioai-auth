"""Shared safety guard for real-Redis integration tests.

PHI P1-5 test-isolation fix: tests/test_interaction_service.py's real-Redis
section defaulted B2_TEST_REDIS_URL to redis://localhost:6380 when unset.
On this project's dev host, localhost:6380 IS the real, single, shared
Redis instance -- the one omnibioai-studio's own compose stack publishes
on host port 6380, carrying live IAM identity caches, the real
`audit:events`/`interactions:events` streams, Celery traffic, and
PHI-capable application caches. That silent default let this "real
backend" test run for real against that shared instance whenever
B2_TEST_REDIS_URL happened to be unset, rather than against a genuinely
isolated instance. Mirrors omnibioai-security-audit's
tests/_mysql_integration_guard.py / tests/_redis_integration_guard.py,
written after the identical silent-default pattern let a MySQL
integration test's teardown destroy real production accounts twice.

Two guards:

1. No implicit default. If the configured env var is unset, these tests
   skip (not fail) -- matching this suite's existing convention of
   skipping rather than failing when an opt-in real backend isn't
   configured.
2. Even when set, port 6380 is refused outright, unconditionally, with no
   override. Production's Redis is always reachable on port 6380 on this
   architecture; a genuinely isolated test instance must run on a
   different port. There is deliberately no escape hatch.

Developer: Manish Kumar <manish@omnibioai.org>
"""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest

FORBIDDEN_PORT = 6380
FORBIDDEN_HOSTS = {"redis", "omnibioai-studio-redis-1"}


class MissingTestRedisEndpoint(RuntimeError):
    """The configured test-Redis env var is not set."""


class ProductionRedisEndpointRejected(RuntimeError):
    """The configured test-Redis env var resolves to this architecture's
    shared, production-adjacent Redis port -- refused unconditionally,
    before any connection is opened."""


class MissingTestRedisAttestation(RuntimeError):
    """The test endpoint lacks explicit isolation attestation."""


def validate_test_redis_url(url_str: str | None, env_var: str) -> str:
    """Pure validation, no pytest side effects.

    Raises MissingTestRedisEndpoint if url_str is falsy, or
    ProductionRedisEndpointRejected if it resolves to port 6380.
    Returns url_str unchanged otherwise.
    """
    if not url_str:
        raise MissingTestRedisEndpoint(
            f"{env_var} is not set -- real-Redis integration tests require "
            "an explicit, isolated test Redis endpoint and never fall back "
            "to a default"
        )
    parsed = urlsplit(url_str)
    if (parsed.hostname or "").lower() in FORBIDDEN_HOSTS:
        raise ProductionRedisEndpointRejected(
            f"{env_var} resolves to the production Redis service hostname -- refusing it"
        )
    port = parsed.port or FORBIDDEN_PORT
    if port == FORBIDDEN_PORT:
        raise ProductionRedisEndpointRejected(
            f"{env_var} resolves to port {FORBIDDEN_PORT}, which is this "
            "architecture's shared, production-adjacent Redis port on this "
            f"host -- refusing to run integration tests against it. Point "
            f"{env_var} at a genuinely isolated test Redis instance on a "
            "different port instead. There is no override for this check."
        )
    return url_str


def validate_test_redis_isolation(
    url_str: str | None, env_var: str, *, attested: str | None,
    database: str | None, key_prefix: str | None,
) -> str:
    url = validate_test_redis_url(url_str, env_var)
    if (
        attested != "1" or database is None or not database.isdigit()
        or not key_prefix or key_prefix.lower() in {"production", "prod"}
    ):
        raise MissingTestRedisAttestation(
            f"{env_var} requires attested isolated database and key prefix"
        )
    return url


def required_test_redis_url(env_var: str) -> str | None:
    """pytest-integrated wrapper: skips the test (missing endpoint) or
    fails it loudly (production endpoint) rather than raising past the
    caller. Returns None only after calling pytest.skip()/pytest.fail(),
    which themselves raise internally -- callers can treat a None return
    as unreachable.
    """
    import os

    try:
        base = env_var.removesuffix("_URL")
        return validate_test_redis_isolation(
            os.environ.get(env_var), env_var,
            attested=os.environ.get(f"{base}_ISOLATION_ATTESTED"),
            database=os.environ.get(f"{base}_DB"),
            key_prefix=os.environ.get(f"{base}_KEY_PREFIX"),
        )
    except MissingTestRedisEndpoint as exc:
        pytest.skip(str(exc))
    except ProductionRedisEndpointRejected as exc:
        pytest.fail(str(exc))
    except MissingTestRedisAttestation as exc:
        pytest.skip(str(exc))
    return None  # pragma: no cover -- pytest.skip/fail always raise
