from passlib.context import CryptContext
from passlib.exc import PasswordSizeError

# HIPAA Phase 1 PR2 discovery: plain bcrypt only ever hashes the first 72
# BYTES of its input -- verified directly (a password differing only past
# byte 72 still verifies as correct against a plain-bcrypt hash). That's a
# silent truncation this PR's own policy explicitly requires not having,
# now that registration is expected to accept substantially-longer-than-
# minimum passphrases. "bcrypt_sha256" is passlib's own built-in scheme
# for exactly this problem: it SHA-256-hashes the password first (a fixed-
# size 32-byte digest, unconditionally under bcrypt's 72-byte limit) and
# bcrypts *that* -- still bcrypt underneath, no new dependency, not a
# switch to a different algorithm for its own sake.
#
# Listing "bcrypt" second (not removed) is what makes this
# backward-compatible: `verify()` detects a hash's scheme from its own
# stored prefix, so every password hash already in the database (plain
# `$2b$...`) keeps verifying exactly as before -- new hashes (registration
# going forward) use bcrypt_sha256, existing ones are untouched, no mass
# rehash or forced reset. `deprecated="auto"` marks every scheme but the
# first as deprecated, so `pwd_context.needs_update(old_hash)` returns
# True for a pre-existing plain-bcrypt hash -- auth_service.authenticate_
# user uses that to opportunistically upgrade a hash to bcrypt_sha256 on
# the user's own next successful login, never eagerly.
pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str):
    # HIPAA Phase 1 PR1 discovery: passlib's bcrypt handler raises
    # PasswordSizeError for a password over its own MAX_PASSWORD_SIZE
    # (4096 bytes) instead of returning False -- previously uncaught
    # here, so POST /auth/login with an oversized password 500'd instead
    # of the normal 401 every other wrong-password path returns. An
    # oversized password is just as wrong as any other wrong password;
    # this makes it behave that way instead of crashing the request.
    try:
        return pwd_context.verify(password, hashed)
    except PasswordSizeError:
        return False


def needs_rehash(hashed: str) -> bool:
    """True for a hash produced by a scheme other than this context's
    current default (e.g. a pre-PR2 plain-bcrypt hash) -- see
    pwd_context's own docstring above. Never raises: an unparseable hash
    is caught by verify_password already failing on it, not this
    function's concern.
    """
    try:
        return pwd_context.needs_update(hashed)
    except Exception:
        return False