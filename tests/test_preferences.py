"""Personal preferences use token ownership and durable, validated columns."""
import uuid

import pytest
from app.db.models import User
from conftest import TestingSessionLocal


@pytest.fixture
def headers(auth_tokens):
    return {"Authorization": f"Bearer {auth_tokens['access_token']}"}


def test_authentication_required(client):
    assert client.get("/me/preferences").status_code == 401
    assert client.patch("/me/preferences", json={"timezone": "UTC"}).status_code == 401


def test_default_and_durable_partial_update(client, headers, registered_user):
    response = client.get("/me/preferences", headers=headers)
    assert response.json() == {"timezone": None}
    assert response.headers["cache-control"] == "no-store"
    assert client.patch("/me/preferences", headers=headers, json={"timezone": "America/Chicago"}).json() == {"timezone": "America/Chicago"}
    assert client.patch("/me/preferences", headers=headers, json={}).json() == {"timezone": "America/Chicago"}
    assert client.get("/me/preferences", headers=headers).json() == {"timezone": "America/Chicago"}
    with TestingSessionLocal() as db:
        user = db.query(User).filter_by(email=registered_user["email"]).one()
        assert user.preferred_timezone == "America/Chicago"
        assert user.email == registered_user["email"]
        assert user.status == "active"
    reset = client.patch("/me/preferences", headers=headers, json={"timezone": None})
    assert reset.json() == {"timezone": None}
    assert reset.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("value", ["CST", "EST", "IST", "Mars/Olympus", "posix/America/Chicago", "../etc/passwd", "/etc/passwd", "", "x" * 101, 42])
def test_invalid_timezone_does_not_persist(client, headers, value):
    assert client.patch("/me/preferences", headers=headers, json={"timezone": value}).status_code == 422
    assert client.get("/me/preferences", headers=headers).json() == {"timezone": None}


@pytest.mark.parametrize("value", ["UTC", "Asia/Kolkata", "America/Indiana/Indianapolis"])
def test_supported_iana_timezone(client, headers, value):
    assert client.patch("/me/preferences", headers=headers, json={"timezone": value}).json() == {"timezone": value}


def test_cross_user_and_unknown_fields(client, headers):
    other = {"email": f"preferences-{uuid.uuid4().hex}@example.test", "password": "TestPassword123!"}
    assert client.post("/auth/register", json=other).status_code == 200
    token = client.post("/auth/login", json=other).json()["access_token"]
    other_headers = {"Authorization": f"Bearer {token}"}
    client.patch("/me/preferences", headers=headers, json={"timezone": "UTC"})
    assert client.get("/me/preferences", headers=other_headers).json() == {"timezone": None}
    assert client.patch("/me/preferences", headers=other_headers, json={"user_id": 1, "timezone": "Asia/Kolkata"}).status_code == 422
    assert client.patch("/me/preferences", headers=headers, json={"appearance": "light"}).status_code == 422
    assert client.get("/me/preferences", headers=headers).json() == {"timezone": "UTC"}


def test_missing_principal_record(client):
    from app.main import app
    from app.rbac import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {"sub": "999999999"}
    try:
        assert client.get("/me/preferences").status_code == 404
        assert client.patch("/me/preferences", json={}).status_code == 404
    finally:
        del app.dependency_overrides[get_current_user]


def test_timezone_migration_preserves_existing_users():
    import importlib.util
    from pathlib import Path
    from sqlalchemy import create_engine, text, inspect
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).parents[1] / "alembic/versions/0030_user_timezone.py"
    spec = importlib.util.spec_from_file_location("timezone_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255))"))
        connection.execute(text("INSERT INTO users VALUES (1, 'migration@example.test')"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            assert connection.execute(text("SELECT preferred_timezone FROM users")).scalar() is None
            migration.downgrade()
        assert [c["name"] for c in inspect(connection).get_columns("users")] == ["id", "email"]
        assert connection.execute(text("SELECT email FROM users")).scalar() == "migration@example.test"
    engine.dispose()
