"""Unit tests for the require_role and require_permission dependency factories: a
user holding the required role or permission is returned unchanged, while a
user with a different role or permission, or none at all, is refused with 403.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest
from fastapi import HTTPException

from app.rbac import require_role, require_permission


def make_user(roles=None, permissions=None):
    """Build a user claims dict with the given roles and permissions."""
    return {
        "sub": "123",
        "email": "test@test.com",
        "roles": roles or [],
        "permissions": permissions or [],
    }


# require_role / require_permission return a FastAPI dependency function.
# Calling it with an explicit `user=` kwarg bypasses the Depends and lets
# us unit-test the authorization logic without a running server.

# ── require_role ──────────────────────────────────────────────────────────────

def test_require_role_passes_with_correct_role():
    """require_role returns the user unchanged when they hold the required role."""
    user = make_user(roles=["admin"])
    checker = require_role("admin")
    result = checker(user=user)
    assert result == user


def test_require_role_fails_with_wrong_role():
    """require_role raises 403 when the user holds only a different role."""
    user = make_user(roles=["user"])
    checker = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        checker(user=user)
    assert exc.value.status_code == 403


def test_require_role_fails_with_no_roles():
    """require_role raises 403 when the user has no roles."""
    user = make_user(roles=[])
    checker = require_role("admin")
    with pytest.raises(HTTPException) as exc:
        checker(user=user)
    assert exc.value.status_code == 403


def test_require_role_passes_when_user_has_multiple_roles():
    """require_role returns the user when the required role is one of several they hold."""
    user = make_user(roles=["user", "admin", "researcher"])
    checker = require_role("researcher")
    result = checker(user=user)
    assert result == user


# ── require_permission ────────────────────────────────────────────────────────

def test_require_permission_passes():
    """require_permission returns the user unchanged when they hold the required permission."""
    user = make_user(permissions=["read:samples"])
    checker = require_permission("read:samples")
    result = checker(user=user)
    assert result == user


def test_require_permission_fails():
    """require_permission raises 403 when the user holds only a different permission."""
    user = make_user(permissions=["read:samples"])
    checker = require_permission("write:samples")
    with pytest.raises(HTTPException) as exc:
        checker(user=user)
    assert exc.value.status_code == 403


def test_require_permission_fails_with_no_permissions():
    """require_permission raises 403 when the user has no permissions."""
    user = make_user(permissions=[])
    checker = require_permission("read:samples")
    with pytest.raises(HTTPException) as exc:
        checker(user=user)
    assert exc.value.status_code == 403
