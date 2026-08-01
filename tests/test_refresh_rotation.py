"""Phase 3 PR0.2: refresh token rotation + reuse detection, and rebuilding
claims from the database at refresh time instead of replaying the
presented token's own stale payload.

Uses the same direct-DB-session pattern as tests/test_apikeys.py and
tests/test_token_revocation.py -- a second connection to the same physical
sqlite file conftest.py's `client` fixture uses, so these tests can grant/
revoke roles and flip User.status directly, which no HTTP route exposes.
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import Permission, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _register_and_login(client, email=None):
    email = email or f"rotate-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _refresh(client, refresh_token):
    return client.post("/auth/refresh", json={"refresh_token": refresh_token})


def _grant_role_with_permission(email: str, role_name: str, permission_name: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = Role(name=role_name)
        perm = Permission(name=permission_name)
        role.permissions.append(perm)
        db.add(role)
        db.add(perm)
        db.flush()
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _remove_role(email: str, role_name: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == role_name).first()
        user.roles.remove(role)
        db.commit()
    finally:
        db.close()


def _suspend_user(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        user.status = "suspended"
        db.commit()
    finally:
        db.close()


# ── Objective 1: claims rebuilt from the database, not replayed ────────────


def test_refresh_returns_a_different_refresh_token(client):
    user = _register_and_login(client)
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 200
    assert resp.json()["refresh_token"] != user["refresh_token"]
    assert resp.json()["access_token"] != user["access_token"]


def test_refresh_after_role_removal_produces_updated_claims(client):
    role_name = f"temp-role-{uuid.uuid4().hex[:8]}"
    perm_name = f"temp-perm-{uuid.uuid4().hex[:8]}"

    user = _register_and_login(client)
    _grant_role_with_permission(user["email"], role_name, perm_name)

    # Log in again so the token actually being refreshed below carries the
    # role -- proves nothing about "does login see current state" (already
    # known), only sets up the precondition for the real assertion: does
    # *refresh*, later, still reflect it correctly once the role is gone.
    relog = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    tokens = relog.json()
    assert role_name in decode_token(tokens["access_token"])["roles"]

    _remove_role(user["email"], role_name)

    resp = _refresh(client, tokens["refresh_token"])
    assert resp.status_code == 200
    new_claims = decode_token(resp.json()["access_token"])

    # This is the behavior PR0.2 fixes: previously /auth/refresh re-signed
    # the *original* token's payload verbatim, so a removed role would
    # still appear here. It must not, now that claims are rebuilt from the
    # database at refresh time.
    assert role_name not in new_claims["roles"]
    assert perm_name not in new_claims["permissions"]


def test_refresh_after_user_suspension_fails(client):
    user = _register_and_login(client)
    _suspend_user(user["email"])

    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


# ── Objective 2: rotation + reuse detection ─────────────────────────────────


def test_replay_of_already_rotated_refresh_token_fails(client):
    user = _register_and_login(client)

    first = _refresh(client, user["refresh_token"])
    assert first.status_code == 200

    # Presenting the *original* (now-rotated) token again is a replay.
    replay = _refresh(client, user["refresh_token"])
    assert replay.status_code == 401


def test_reuse_detection_revokes_the_entire_token_family(client):
    """The legitimately-rotated descendant token must also stop working
    once a replay of its ancestor is detected -- reuse detection revokes
    the whole family, not just the token that was replayed, since at the
    point of detection this service cannot tell whether the *original*
    caller or the *rotated* token is the one actually held by an attacker.
    """
    user = _register_and_login(client)

    first = _refresh(client, user["refresh_token"])
    assert first.status_code == 200
    rotated_token = first.json()["refresh_token"]

    # Replay the original -- triggers family-wide revocation.
    replay = _refresh(client, user["refresh_token"])
    assert replay.status_code == 401

    # The legitimately-issued descendant token is now also dead.
    descendant_attempt = _refresh(client, rotated_token)
    assert descendant_attempt.status_code == 401


def test_rotation_chain_of_three_all_work_in_sequence(client):
    """Sanity: normal sequential rotation (no replay) keeps working across
    multiple refreshes -- each new token is valid for exactly one more
    refresh, not just the first."""
    user = _register_and_login(client)

    r1 = _refresh(client, user["refresh_token"])
    assert r1.status_code == 200
    token_2 = r1.json()["refresh_token"]

    r2 = _refresh(client, token_2)
    assert r2.status_code == 200
    token_3 = r2.json()["refresh_token"]

    r3 = _refresh(client, token_3)
    assert r3.status_code == 200

    # token_2 was already consumed by r2 above -- presenting it again now
    # is itself a replay.
    replay = _refresh(client, token_2)
    assert replay.status_code == 401
