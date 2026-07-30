import os

from cryptography.fernet import Fernet

# Encrypts GlobalConfig's credential fields at rest (config_service.py).
# Two distinct failure modes, deliberately handled differently:
#
#   - UNSET (operator hasn't configured this feature yet): the service
#     still starts -- same "empty defaults = feature disabled, don't block
#     startup" convention already used for OAuth2 SSO in this codebase
#     (core/config.py's GOOGLE_OAUTH_CLIENT_ID etc.) -- but encrypt()
#     raises the moment anything actually tries to write config, so
#     there's no path that silently stores plaintext.
#   - MALFORMED (operator set it to something that isn't a valid Fernet
#     key): this is a deploy misconfiguration, not "not configured yet" --
#     refuses to start at all, immediately and loudly, rather than
#     silently limping along with a broken key that would only surface as
#     a confusing error whenever someone first tries to use the feature.
_RAW_KEY = os.environ.get("CONFIG_ENCRYPTION_KEY")

if _RAW_KEY:
    try:
        _fernet = Fernet(_RAW_KEY.encode())
    except Exception as e:
        raise RuntimeError(
            "CONFIG_ENCRYPTION_KEY is set but is not a valid Fernet key "
            "(expected 32 url-safe base64-encoded bytes). Generate one with:\n"
            '    python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"\n'
            "Refusing to start with a malformed encryption key rather than "
            "risk it silently failing later or falling back to plaintext."
        ) from e
else:
    _fernet = None


def is_configured() -> bool:
    return _fernet is not None


def encrypt(plaintext: str) -> str:
    if _fernet is None:
        raise RuntimeError(
            "CONFIG_ENCRYPTION_KEY is not set -- refusing to store "
            "credentials without encryption. Set CONFIG_ENCRYPTION_KEY "
            "(see the format note above) before writing global config."
        )
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if _fernet is None:
        raise RuntimeError("CONFIG_ENCRYPTION_KEY is not set -- cannot decrypt stored config.")
    return _fernet.decrypt(ciphertext.encode()).decode()
