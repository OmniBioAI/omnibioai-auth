from datetime import datetime, timedelta
from jose import jwt
from app.core.config import settings

import uuid

def create_access_token(data: dict):
    to_encode = data.copy()

    to_encode.update({
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "type": "access",
        "jti": str(uuid.uuid4())   # 👈 IMPORTANT
    })

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)    


def create_refresh_token(data: dict):
    to_encode = data.copy()
    to_encode.update({
        "exp": datetime.utcnow() + timedelta(days=7),
        "type": "refresh",
        "jti": str(uuid.uuid4())   # without this, same-second logins collide on the refresh_tokens.token UNIQUE constraint
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def create_oauth_state_token(provider: str):
    """Short-lived, self-contained CSRF token for the OAuth authorize step.
    Avoids needing server-side session storage — verified purely by
    signature + expiry on callback, consistent with the rest of this
    service's stateless JWT approach."""
    return jwt.encode(
        {
            "type": "oauth_state",
            "provider": provider,
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )


def create_link_token(user_id: int, provider: str, provider_user_id: str, email: str):
    """Short-lived token proving an OAuth exchange resolved to `user_id`'s
    existing email, pending password confirmation via POST /auth/link/confirm."""
    return jwt.encode(
        {
            "type": "oauth_link",
            "user_id": user_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "email": email,
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        },
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

