from passlib.context import CryptContext
from passlib.exc import PasswordSizeError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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