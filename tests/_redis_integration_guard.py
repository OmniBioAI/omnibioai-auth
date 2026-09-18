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


class MissingTestRedisEndpoint(RuntimeError):
    """The configured test-Redis env var is not set."""


class ProductionRedisEndpointRejected(RuntimeError):
    """The configured test-Redis env var resolves to this architecture's
    shared, production-adjacent Redis port -- refused unconditionally,
    before any connection is opened."""


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
    port = urlsplit(url_str).port or FORBIDDEN_PORT
    if port == FORBIDDEN_PORT:
        raise ProductionRedisEndpointRejected(
            f"{env_var} resolves to port {FORBIDDEN_PORT}, which is this "
            "architecture's shared, production-adjacent Redis port on this "
            f"host -- refusing to run integration tests against it. Point "
            f"{env_var} at a genuinely isolated test Redis instance on a "
            "different port instead. There is no override for this check."
        )
    return url_str


def required_test_redis_url(env_var: str) -> str | None:
    """pytest-integrated wrapper: skips the test (missing endpoint) or
    fails it loudly (production endpoint) rather than raising past the
    caller. Returns None only after calling pytest.skip()/pytest.fail(),
    which themselves raise internally -- callers can treat a None return
    as unreachable.
    """
    import os

    try:
        return validate_test_redis_url(os.environ.get(env_var), env_var)
    except MissingTestRedisEndpoint as exc:
        pytest.skip(str(exc))
    except ProductionRedisEndpointRejected as exc:
        pytest.fail(str(exc))
    return None  # pragma: no cover -- pytest.skip/fail always raise
