from pydantic import BaseModel


class MintUserTokenRequest(BaseModel):
    email: str


# Mirrors AuthorizationCodeTokenResponse/ClientCredentialsTokenResponse's
# shape (app/schemas/oauth_client.py) -- the established "here is a bearer
# token" response convention in this repo. No `scope` field: unlike those
# two, the minted token's permissions come entirely from the target
# user's own real role/membership (build_user_claims), never from a
# scope negotiated on this request.
class MintUserTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
