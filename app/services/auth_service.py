from datetime import datetime, timedelta
from app.db.models import User, RefreshToken
from app.core.security import verify_password
from app.core.jwt import create_access_token, create_refresh_token


def authenticate_user(db, email, password):
    user = db.query(User).filter(User.email == email).first()

    if not user or user.status != "active":
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


def generate_tokens(db, user):
    permissions = sorted({p.name for r in user.roles for p in r.permissions})

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "roles": [r.name for r in user.roles],
        "permissions": permissions
    }

    access = create_access_token(payload)
    refresh = create_refresh_token(payload)

    db_token = RefreshToken(
        user_id=user.id,
        token=refresh,
        revoked=False,
        expires_at=datetime.utcnow() + timedelta(days=7)
    )

    db.add(db_token)
    db.commit()

    return access, refresh


def revoke_token(db, token):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if db_token:
        db_token.revoked = True
        db.commit()


def validate_refresh_token(db, token):
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token,
        RefreshToken.revoked == False
    ).first()

    if not db_token:
        return None

    if db_token.expires_at < datetime.utcnow():
        return None

    return db_token