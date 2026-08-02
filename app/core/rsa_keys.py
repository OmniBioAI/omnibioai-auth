"""SSO Phase 2 PR15: RS256/JWKS foundation.

Loads (or, in dev/test, generates) the RSA keypair used to sign RS256
tokens and expose their public half via GET /.well-known/jwks.json.
Kept as its own module (rather than folded into config.py/jwt.py) since
key material and its PEM/JWK encoding is a distinct concern from either
settings loading or token issuance, and both routes_jwks.py and
core/jwt.py need it.
"""

import hashlib
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk as jose_jwk

from app.core.config import settings

logger = logging.getLogger(__name__)


def _normalize_pem(value: str) -> bytes:
    # Multi-line PEM doesn't survive most single-line env var mechanisms
    # (docker-compose env_file, Kubernetes env vars) without the newlines
    # being escaped -- tolerate a literal "\n" as well as a real one.
    return value.replace("\\n", "\n").encode()


def _load_or_generate_keys():
    if settings.JWT_PRIVATE_KEY:
        private_key = serialization.load_pem_private_key(
            _normalize_pem(settings.JWT_PRIVATE_KEY), password=None
        )
    else:
        # No configured key: generate an ephemeral, process-local keypair so
        # RS256/JWKS work out of the box in dev/test. NOT safe for
        # production use -- tokens it signs stop verifying on the next
        # restart, and a multi-replica deployment would mint a different
        # key per replica. Any real deployment that sets JWT_ALGORITHM=RS256
        # must also set JWT_PRIVATE_KEY/JWT_PUBLIC_KEY explicitly.
        logger.warning(
            "JWT_PRIVATE_KEY not set -- generating an ephemeral in-process RSA "
            "keypair. Fine for dev/test; do NOT rely on this in production."
        )
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    if settings.JWT_PUBLIC_KEY:
        public_key = serialization.load_pem_public_key(_normalize_pem(settings.JWT_PUBLIC_KEY))
    else:
        public_key = private_key.public_key()

    return private_key, public_key


_private_key, _public_key = _load_or_generate_keys()

PRIVATE_KEY_PEM = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()

PUBLIC_KEY_PEM = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# Stable identifier for this keypair, derived from the public key itself
# (not random) so it's reproducible across a restart when the same key
# material is configured, and changes automatically if the key ever does --
# a real prerequisite for a future multi-key JWKS during key rotation, even
# though this PR only ever publishes one key.
KID = hashlib.sha256(PUBLIC_KEY_PEM.encode()).hexdigest()[:16]


def public_jwk() -> dict:
    """JWKS-format ({kty, n, e, ...}) representation of the public key."""
    key_dict = jose_jwk.construct(PUBLIC_KEY_PEM, algorithm="RS256").to_dict()
    key_dict["kid"] = KID
    key_dict["use"] = "sig"
    key_dict["alg"] = "RS256"
    return key_dict
