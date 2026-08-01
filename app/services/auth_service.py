from datetime import datetime, timedelta
from app.db.models import User, RefreshToken
from app.core.security import verify_password
from app.core.jwt import create_access_token, create_refresh_token
from app.services import org_service, permission_parity


def authenticate_user(db, email, password):
    user = db.query(User).filter(User.email == email).first()

    if not user or user.status != "active":
        return None

    if not user.hashed_password:
        return None  # OAuth-only account — no password set

    if not verify_password(password, user.hashed_password):
        return None

    return user


def generate_tokens(db, user, auth_method: str = "password"):
    """`auth_method` records which flow issued this token ("password" |
    "oauth" | "license") -- purely informational, not used for any
    authorization decision.

    Phase 1 PR3: payload gains org_id/org_role/auth_method/token_version=2,
    all additive -- sub/email/roles/permissions are computed exactly as
    before and never removed, so anything reading only those (existing
    require_permission, existing /auth/validate consumers) is unaffected.
    org_id/org_role reflect the user's resolved primary org membership
    (None/[] if they don't have one yet -- a valid state, not an error, for
    any account that predates the Default Org backfill). The parity check
    below is observational only: it logs drift between the legacy global
    permission set and the new org-scoped one, but `permissions` below
    remains the global computation -- nothing about what's actually
    enforced changes in this PR.
    """
    permissions = sorted({p.name for r in user.roles for p in r.permissions})

    org_membership = org_service.resolve_primary_membership(db, user.id)
    org_id = org_membership.organization_id if org_membership else None
    org_role = sorted(r.name for r in org_membership.roles) if org_membership else []

    if org_membership is not None:
        permission_parity.check_and_log(user, permissions, org_membership)

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "roles": [r.name for r in user.roles],
        "permissions": permissions,
        "org_id": org_id,
        "org_role": org_role,
        "auth_method": auth_method,
        "token_version": 2,
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