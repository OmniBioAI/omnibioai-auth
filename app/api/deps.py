"""
OmniBioAI app.api.deps.

Purpose:
    Defines get_current_user and require_permission for app.api.deps.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from app.core.jwt import decode_token

security = HTTPBearer()

def get_current_user(token=Depends(security)):
    try:
        return decode_token(token.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_permission(permission: str):
    def wrapper(user=Depends(get_current_user)):
        perms = user.get("permissions", [])
        if permission not in perms:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return wrapper