"""PR0.1: get_current_user must enforce the same revocation/suspension
checks /auth/validate already performed inline, via the shared
app.core.token_revocation.assert_token_usable helper.

Uses the same direct-DB-session pattern as tests/test_apikeys.py and
tests/test_sso_enforcement.py -- a second connection to the same physical
sqlite file conftest.py's `client` fixture uses, so these tests can
manipulate rows (RevokedToken, User.status) that no HTTP route exposes a
way to create/set directly.
"""
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.core.token_revocation import assert_token_usable
from app.db.models import RevokedToken, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"revoke-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


# `GET /orgs` (list_my_orgs) depends on bare get_current_user -- no
# permission/org-membership check beyond "is this a valid token" -- making
# it the simplest existing route to exercise get_current_user's own
# behavior in isolation.
def _get_orgs(client, access_token):
    return client.get("/orgs", headers=_auth_header(access_token))


# ── get_current_user, through a real protected route ────────────────────────


def test_valid_active_token_still_works(client):
    user = _register_and_login(client)
    resp = _get_orgs(client, user["access_token"])
    assert resp.status_code == 200


def test_blacklisted_access_token_rejected_by_protected_route(client):
    user = _register_and_login(client)

    # Sanity: works before logout.
    assert _get_orgs(client, user["access_token"]).status_code == 200

    client.post(
        "/auth/logout",
        json={"refresh_token": user["refresh_token"], "access_token": user["access_token"]},
    )

    # Previously, get_current_user only checked signature/expiry, so a
    # blacklisted-but-not-yet-expired access token still worked here even
    # after logout -- this is exactly the gap PR0.1 closes.
    resp = _get_orgs(client, user["access_token"])
    assert resp.status_code == 401


def test_revoked_tokens_db_entry_rejected_by_protected_route(client):
    user = _register_and_login(client)
    assert _get_orgs(client, user["access_token"]).status_code == 200

    jti = decode_token(user["access_token"])["jti"]
    db = _DirectSession()
    try:
        db.add(RevokedToken(token_jti=jti))
        db.commit()
    finally:
        db.close()

    resp = _get_orgs(client, user["access_token"])
    assert resp.status_code == 401


def test_suspended_user_rejected_by_protected_route(client):
    user = _register_and_login(client)
    assert _get_orgs(client, user["access_token"]).status_code == 200

    db = _DirectSession()
    try:
        db_user = db.query(User).filter(User.email == user["email"]).first()
        db_user.status = "suspended"
        db.commit()
    finally:
        db.close()

    # The access token itself is untouched -- still validly signed,
    # unexpired, not blacklisted, not in revoked_tokens. Only the
    # underlying account's status changed. Previously this had zero effect
    # on get_current_user; it must now reject the token immediately.
    resp = _get_orgs(client, user["access_token"])
    assert resp.status_code == 401


# A full end-to-end regression check that a real client_credentials token
# (no sub/email at all) is still rejected by every get_current_user-gated
# route already exists: tests/test_oauth_token.py::
# test_service_token_rejected_by_get_current_user_dependent_route. The
# unit-level equivalent for assert_token_usable itself is below
# (test_assert_token_usable_skips_status_check_when_sub_absent).


# ── assert_token_usable, unit-level ──────────────────────────────────────────


def _make_active_user(email=None):
    email = email or f"unit-{uuid.uuid4().hex[:8]}@omnibioai.test"
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password="x", status="active")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    finally:
        db.close()


def test_assert_token_usable_passes_for_active_user_no_revocation(client):
    user_id = _make_active_user()
    db = _DirectSession()
    try:
        assert_token_usable({"sub": str(user_id), "jti": str(uuid.uuid4())}, db)
    finally:
        db.close()


def test_assert_token_usable_raises_for_blacklisted_jti(client):
    from app.core import token_revocation

    user_id = _make_active_user()
    jti = str(uuid.uuid4())
    token_revocation._blacklist.setex(f"blacklist:jti:{jti}", 60, "1")

    db = _DirectSession()
    try:
        with pytest.raises(HTTPException) as exc:
            assert_token_usable({"sub": str(user_id), "jti": jti}, db)
        assert exc.value.status_code == 401
    finally:
        db.close()


def test_assert_token_usable_fails_open_when_redis_is_unreachable(client, monkeypatch):
    """A Redis outage must not turn into a 500 for every authenticated
    request in the service -- assert_token_usable runs inside
    get_current_user, which every route depends on. Fails open
    specifically for the blacklist check (matches _blacklist_access_
    token's own established "fail open -- never block logout"
    philosophy); the RevokedToken/User.status checks below it are
    unaffected and still run normally."""
    from app.core import token_revocation

    def _boom(*args, **kwargs):
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr(token_revocation._blacklist, "exists", _boom)

    user_id = _make_active_user()
    db = _DirectSession()
    try:
        # Does not raise, despite Redis being unreachable.
        assert_token_usable({"sub": str(user_id), "jti": str(uuid.uuid4())}, db)
    finally:
        db.close()


def test_assert_token_usable_raises_for_revoked_token_row():
    user_id = _make_active_user()
    jti = str(uuid.uuid4())
    db = _DirectSession()
    try:
        db.add(RevokedToken(token_jti=jti))
        db.commit()

        with pytest.raises(HTTPException) as exc:
            assert_token_usable({"sub": str(user_id), "jti": jti}, db)
        assert exc.value.status_code == 401
    finally:
        db.close()


def test_assert_token_usable_raises_for_inactive_user():
    email = f"inactive-{uuid.uuid4().hex[:8]}@omnibioai.test"
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password="x", status="suspended")
        db.add(user)
        db.commit()
        db.refresh(user)

        with pytest.raises(HTTPException) as exc:
            assert_token_usable({"sub": str(user.id), "jti": str(uuid.uuid4())}, db)
        assert exc.value.status_code == 401
    finally:
        db.close()


def test_assert_token_usable_raises_for_nonexistent_user():
    db = _DirectSession()
    try:
        with pytest.raises(HTTPException) as exc:
            assert_token_usable({"sub": "99999999", "jti": str(uuid.uuid4())}, db)
        assert exc.value.status_code == 401
    finally:
        db.close()


def test_assert_token_usable_skips_status_check_when_sub_absent():
    """A client_credentials-shaped payload has no `sub` at all -- this must
    not crash trying to look up a user that was never supposed to exist;
    rejecting such tokens from user-identity checks stays get_current_user's
    own job (its auth_method check), not this function's."""
    db = _DirectSession()
    try:
        assert_token_usable({"jti": str(uuid.uuid4()), "auth_method": "client_credentials"}, db)
    finally:
        db.close()
