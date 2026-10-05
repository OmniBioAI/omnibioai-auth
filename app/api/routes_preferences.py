"""Personal preferences belong to the authenticated IAM user, not an organization."""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.preferences import PreferencesOut, PreferencesPatch

router = APIRouter(prefix="/me/preferences", tags=["preferences"])


def own_user(db, principal):
    user = db.get(User, int(principal["sub"]))
    if user is None:
        raise HTTPException(404, "User not found")
    return user


@router.get("", response_model=PreferencesOut)
def get_preferences(response: Response, db: Session = Depends(get_db), principal=Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    return PreferencesOut(timezone=own_user(db, principal).preferred_timezone)


@router.patch("", response_model=PreferencesOut)
def update_preferences(body: PreferencesPatch, response: Response, db: Session = Depends(get_db), principal=Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    user = own_user(db, principal)
    # Only supplied columns are updated. Independent fields are never replaced
    # as a JSON document; concurrent writes to this field are last-commit-wins.
    if "timezone" in body.model_fields_set:
        user.preferred_timezone = body.timezone
        db.commit()
        db.refresh(user)
    return PreferencesOut(timezone=user.preferred_timezone)
