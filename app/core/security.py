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

# HIPAA Phase 4: login timing side-channel closure
# (app/services/auth_service.py::authenticate_user). A fixed, precomputed
# hash of an arbitrary placeholder string -- never a real credential,
# never compared against anything meaningful. Its only purpose is to give
# every login-failure branch that currently has no real user/password-
# hash to check against (unknown email, inactive account, password-less
# OAuth-only account) something to run a real bcrypt-cost verification
# against, so that branch costs the same CPU time as the "real account,
# wrong password" branch below -- see that function's own docstring and
# docs/security-login-timing-side-channel.md for the full design.
#
# Computed once, at import time (this module's current CryptContext
# default -- "bcrypt_sha256" -- same scheme/cost factor real
# registration hashes use), not hardcoded as a literal string: this way
# it always matches whatever this process's actual default hashing cost
# is, including if that default is ever changed, without a second place
# to remember to update. The one-time cost (same order of magnitude as
# hashing any other password) is paid once per process start, the same
# category of startup cost `_redis`/`_pub`'s own module-level connections
# already pay elsewhere in this service -- not a per-request cost.
DUMMY_PASSWORD_HASH = pwd_context.hash("omnibioai-timing-equalization-placeholder-not-a-real-credential")


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