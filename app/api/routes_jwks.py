from fastapi import APIRouter

from app.core.rsa_keys import public_jwk

# RFC 8615 "well-known URI" -- conventionally served at the root of the
# service, not nested under /auth like the rest of this file's siblings,
# so a verifier can fetch it without knowing anything about this service's
# other routes.
router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
def jwks():
    return {"keys": [public_jwk()]}
