import os
import pytest
from unittest.mock import patch

# Must be set before any app module is imported so config.settings has a key.
os.environ.setdefault("SECRET_KEY", "test-secret-key-omnibioai-32-chars-x!")

# create_admin() (called at app import time, below) no longer bakes in a
# hardcoded default password -- give it a fixed, known-to-tests-only value
# via the same env-var override a real deployment would use, rather than
# letting it fall back to a per-run random password tests can't predict.
os.environ.setdefault("ADMIN_BOOTSTRAP_PASSWORD", "test-admin-password-not-for-prod")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///./test.db"

test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=test_engine
)

# Patch db.session BEFORE importing app.main.
# app/main.py calls Base.metadata.create_all(bind=engine) at module level,
# so the SQLite engine must be in place before that code runs.
import app.db.session as _db_session

_db_session.engine = test_engine
_db_session.SessionLocal = TestingSessionLocal

from app.main import app  # noqa: E402 — intentional late import
from app.db.base import Base
from app.db.session import get_db
from fastapi.testclient import TestClient


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture(scope="session")
def client(setup_db):
    app.dependency_overrides[get_db] = override_get_db

    _blacklisted = {}

    def _setex(key, ttl, value):
        _blacklisted[key] = value
        return True

    def _exists(key):
        return 1 if key in _blacklisted else 0

    # HIPAA Phase 1 PR1 (login_throttle_service/rate_limit): a real
    # fakeredis instance, not a hand-mocked stub, so the atomic Lua
    # scripts in app/core/rate_limit.py get real coverage (INCR/EXPIRE/
    # SET-with-TTL semantics matter for this feature, unlike the simple
    # setex/exists calls _blacklisted above stands in for). Patched at
    # session scope, same as _pub/_blacklist above, since app.main (and
    # therefore app.core.rate_limit's module-level `_redis`) is only
    # imported once per test session.
    import fakeredis
    fake_redis = fakeredis.FakeStrictRedis(decode_responses=True)

    with patch("app.api.routes_auth._pub") as mock_pub, \
         patch("app.core.token_revocation._blacklist") as mock_bl, \
         patch("app.core.rate_limit._redis", fake_redis):
        mock_pub.publish.return_value = None
        mock_bl.setex.side_effect = _setex
        mock_bl.exists.side_effect = _exists
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_rate_limit_state(client):
    """Every test in this session shares one `client`/TestClient, which
    means one source IP (starlette's TestClient default) for the entire
    run. Without a reset, login-throttling state from one test (this
    PR's own tests deliberately drive accounts/IPs into lockout) would
    leak into the next. Runs before AND after every test, not just
    before -- a test that raises partway through a throttle scenario
    must not poison whatever runs next either. Autouse so this applies
    uniformly, without every existing (pre-this-PR) test file needing to
    know this fixture exists.
    """
    import app.core.rate_limit as rate_limit_module

    def _reset():
        try:
            rate_limit_module._redis.flushdb()
        except Exception:
            pass
        rate_limit_module._fallback._counters.clear()
        rate_limit_module._fallback._locks.clear()

    _reset()
    yield
    _reset()


@pytest.fixture
def registered_user(client):
    """Register a unique user per test.

    create_refresh_token has no jti/random component, so two logins for the
    same user within the same second produce identical JWT strings and collide
    on the UNIQUE constraint in refresh_tokens.  A per-test unique email
    ensures each test's login inserts a distinct token.
    """
    import uuid

    email = f"test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    resp = client.post("/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 200
    return {"email": email, "password": password}


@pytest.fixture
def auth_tokens(client, registered_user):
    """Fresh login tokens for each test that needs them."""
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    return resp.json()
