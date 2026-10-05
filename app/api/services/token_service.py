"""
OmniBioAI app.api.services.token_service.

Purpose:
    Defines is_token_revoked and revoke_token for app.api.services.token_service.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from app.db.models import RevokedToken
from app.core.jwt import decode_token


def is_token_revoked(db, jti: str) -> bool:
    return db.query(RevokedToken).filter(
        RevokedToken.token_jti == jti
    ).first() is not None


def revoke_token(db, token_payload):
    jti = token_payload.get("jti")

    if jti:
        db.add(RevokedToken(token_jti=jti))
        db.commit()