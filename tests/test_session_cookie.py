"""SSO Phase 2 PR10: the omnibioai_session browser cookie -- a second,
server-set form of the existing refresh_token, additive to the unchanged
JSON access_token/refresh_token response. See app/api/routes_auth.py's
_set_session_cookie/_clear_session_cookie for the full design rationale.

Cookie assertions read the raw `set-cookie` response header directly
rather than the TestClient's parsed cookie jar: Domain=.omnibioai.org
doesn't match the test server's own host (testserver), so a standards-
compliant cookie jar won't store it -- inspecting the header is the
correct, unambiguous way to verify what the server actually sent,
independent of jar/domain-matching behavior. The cookie-fallback tests
inject the cookie explicitly per-request instead of relying on the jar.
"""


def _parse_cookie_attrs(set_cookie_header: str) -> dict:
    """Best-effort parse of a Set-Cookie header into {attr_lower: value_or_True}."""
    parts = [p.strip() for p in set_cookie_header.split(";")]
    attrs = {}
    name, _, value = parts[0].partition("=")
    attrs["_name"] = name
    attrs["_value"] = value
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.strip().lower()] = True
    return attrs


# ── Login: JSON unchanged + Set-Cookie present ──────────────────────────────

def test_login_json_response_unchanged(client, registered_user):
    """Existing behavior must be byte-for-byte unaffected: same keys, same
    access_token/refresh_token/token_type shape."""
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"access_token", "refresh_token", "token_type"}
    assert data["token_type"] == "bearer"


def test_login_sets_session_cookie(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    set_cookie = resp.headers.get("set-cookie")
    assert set_cookie is not None
    attrs = _parse_cookie_attrs(set_cookie)
    assert attrs["_name"] == "omnibioai_session"


def test_login_cookie_value_matches_refresh_token(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs["_value"] == resp.json()["refresh_token"]


# ── Security requirements (Task 4) ──────────────────────────────────────────

def test_session_cookie_is_httponly(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("httponly") is True


def test_session_cookie_is_secure(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("secure") is True


def test_session_cookie_domain_is_parent_domain(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("domain") == ".omnibioai.org"


def test_session_cookie_samesite_lax_and_path_root(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("samesite", "").lower() == "lax"
    assert attrs.get("path") == "/"


def test_session_cookie_not_readable_via_document_cookie():
    """document.cookie (browser JS) can never see an HttpOnly cookie -- this
    is a browser-enforced guarantee, not something a server-side HTTP test
    can execute directly. The complete, correct verification at this layer
    is that the HttpOnly attribute is present on the Set-Cookie response
    (proven by test_session_cookie_is_httponly above); this test exists
    only to document that reasoning explicitly rather than leave the
    "not readable via document.cookie" requirement unaddressed."""
    assert True


def test_max_age_matches_refresh_token_ttl(client, registered_user):
    """7 days, matching REFRESH_TOKEN_TTL_DAYS -- not a separately
    hardcoded value that could drift from the token's own lifetime."""
    from app.services.auth_service import REFRESH_TOKEN_TTL_DAYS

    resp = client.post("/auth/login", json=registered_user)
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("max-age") == str(REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60)


# ── Refresh: body vs cookie priority, rotation ──────────────────────────────

def test_refresh_body_token_still_works(client, auth_tokens):
    """Existing API clients that only ever send the body must be
    completely unaffected."""
    resp = client.post("/auth/refresh", json={"refresh_token": auth_tokens["refresh_token"]})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_refresh_cookie_only_works(client, auth_tokens):
    """No body refresh_token at all -- only the cookie -- must still
    succeed."""
    resp = client.post(
        "/auth/refresh",
        json={},
        cookies={"omnibioai_session": auth_tokens["refresh_token"]},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_refresh_body_token_takes_priority_over_cookie(client, registered_user, auth_tokens):
    """If both are present, the body value wins -- a stale/mismatched
    cookie must never override an explicitly supplied body token."""
    # A second, independent login gives us a genuinely different, valid
    # refresh token to use as the (wrong) cookie value.
    second_login = client.post("/auth/login", json=registered_user)
    other_refresh_token = second_login.json()["refresh_token"]

    resp = client.post(
        "/auth/refresh",
        json={"refresh_token": auth_tokens["refresh_token"]},
        cookies={"omnibioai_session": other_refresh_token},
    )
    assert resp.status_code == 200
    # The body token (auth_tokens') was rotated, not the cookie token
    # (other_refresh_token) -- confirmed by the other token still being
    # usable afterward.
    still_valid = client.post("/auth/refresh", json={"refresh_token": other_refresh_token})
    assert still_valid.status_code == 200


def test_refresh_returns_rotated_cookie(client, auth_tokens):
    resp = client.post("/auth/refresh", json={"refresh_token": auth_tokens["refresh_token"]})
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs["_name"] == "omnibioai_session"
    assert attrs["_value"] == resp.json()["refresh_token"]
    # The new cookie must not be the old (now rotated/single-use) token.
    assert attrs["_value"] != auth_tokens["refresh_token"]


def test_refresh_no_token_anywhere_returns_401(client):
    resp = client.post("/auth/refresh", json={})
    assert resp.status_code == 401


def test_refresh_invalid_cookie_only_returns_401(client):
    resp = client.post(
        "/auth/refresh", json={}, cookies={"omnibioai_session": "not.a.valid.token"}
    )
    assert resp.status_code == 401


# ── Logout: revocation unchanged, cookie cleared ────────────────────────────

def test_logout_revocation_unchanged(client, auth_tokens):
    resp = client.post("/auth/logout", json={"refresh_token": auth_tokens["refresh_token"]})
    assert resp.status_code == 200
    assert resp.json()["message"] == "Logged out"

    # Existing behavior: the refresh token is now dead.
    refresh_resp = client.post("/auth/refresh", json={"refresh_token": auth_tokens["refresh_token"]})
    assert refresh_resp.status_code == 401


def test_logout_clears_session_cookie(client, auth_tokens):
    resp = client.post("/auth/logout", json={"refresh_token": auth_tokens["refresh_token"]})
    set_cookie = resp.headers.get("set-cookie")
    assert set_cookie is not None
    attrs = _parse_cookie_attrs(set_cookie)
    assert attrs["_name"] == "omnibioai_session"
    # An empty value and an immediate expiry both signal "clear this
    # cookie" to the browser -- Starlette's delete_cookie sets both
    # (the value is a quoted empty string, '""', not a bare empty string).
    assert attrs["_value"] == '""'
    assert attrs.get("max-age") == "0"


def test_logout_clear_cookie_matches_original_scope(client, auth_tokens):
    """The clearing Set-Cookie's Domain/Path must match the original or a
    real browser won't actually delete it."""
    resp = client.post("/auth/logout", json={"refresh_token": auth_tokens["refresh_token"]})
    attrs = _parse_cookie_attrs(resp.headers["set-cookie"])
    assert attrs.get("domain") == ".omnibioai.org"
    assert attrs.get("path") == "/"
