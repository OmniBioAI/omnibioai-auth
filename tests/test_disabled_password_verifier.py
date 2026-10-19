from app.core.security import verify_password


def test_disabled_or_malformed_password_verifier_is_controlled_failure():
    for verifier in (None, "", "!disabled!", "not-a-passlib-hash"):
        assert verify_password("synthetic-password", verifier) is False
