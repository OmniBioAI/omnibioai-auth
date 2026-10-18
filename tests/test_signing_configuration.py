"""Production signing configuration must not fall back to ephemeral keys."""
import os
import subprocess
import sys
from pathlib import Path


AUTH_ROOT = Path(__file__).resolve().parents[1]


def _run_auth_import(extra_env):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(AUTH_ROOT),
        "PYTHON_DOTENV_DISABLED": "true",
        "APP_ENV": "production",
        **extra_env,
    }
    return subprocess.run(
        [sys.executable, "-c", "import app.core.rsa_keys"],
        cwd=AUTH_ROOT, env=env, text=True, capture_output=True, timeout=10,
    )


def test_production_fails_closed_without_persistent_hs256_key():
    result = _run_auth_import({})
    assert result.returncode != 0
    assert "Production Auth requires a persistent SECRET_KEY" in result.stderr
    assert "ephemeral" not in result.stderr.lower()


def test_hs256_production_does_not_generate_ephemeral_rsa_keypair():
    result = _run_auth_import({
        "SECRET_KEY": "synthetic-test-signing-secret-at-least-32-bytes",
    })
    assert result.returncode == 0, result.stderr
    assert "ephemeral" not in result.stderr.lower()
    check = subprocess.run(
        [sys.executable, "-c",
         "from app.core.rsa_keys import PRIVATE_KEY_PEM, PUBLIC_KEY_PEM; "
         "assert PRIVATE_KEY_PEM is None and PUBLIC_KEY_PEM is None"],
        cwd=AUTH_ROOT, env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(AUTH_ROOT), "PYTHON_DOTENV_DISABLED": "true",
            "APP_ENV": "production",
            "SECRET_KEY": "synthetic-test-signing-secret-at-least-32-bytes",
        }, text=True, capture_output=True, timeout=10,
    )
    assert check.returncode == 0, check.stderr


def test_production_rejects_unapproved_rs256_algorithm():
    result = _run_auth_import({
        "SECRET_KEY": "synthetic-test-signing-secret-at-least-32-bytes",
        "JWT_ALGORITHM": "RS256",
    })
    assert result.returncode != 0
    assert "approved HS256 contract" in result.stderr
