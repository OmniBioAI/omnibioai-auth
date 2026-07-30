from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.session import get_db
from app.rbac import get_current_user, require_permission
from app.schemas.config import GlobalConfigIn, GlobalConfigOut
from app.services import config_service

# Mounted under the already-owned, already-routed /auth/ prefix
# (nginx-router.conf passes /auth/* straight through) rather than a new
# bare /config -- a generic top-level name like that is exactly the kind
# of collision-prone bare path this session's earlier work (issue #5/#6)
# was built around avoiding, and it would need its own new nginx location
# for no benefit over reusing /auth/'s existing one.
router = APIRouter(prefix="/auth", tags=["config"])

MANAGE_CONFIG = "manage_config"


def _to_out(db: Session, config) -> GlobalConfigOut:
    updated_by_email = None
    if config and config.updated_by_user_id:
        user = db.query(User).filter(User.id == config.updated_by_user_id).first()
        updated_by_email = user.email if user else None

    return GlobalConfigOut(
        llm_provider=config.llm_provider if config else None,
        has_llm_api_key=bool(config and config.llm_api_key_encrypted),
        cloud_provider=config.cloud_provider if config else None,
        has_cloud_credentials=bool(config and config.cloud_credentials_encrypted),
        work_directory=config.work_directory if config else None,
        data_directory=config.data_directory if config else None,
        updated_at=config.updated_at.isoformat() if config and config.updated_at else None,
        updated_by_email=updated_by_email,
    )


@router.get("/config", response_model=GlobalConfigOut)
def get_config(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),  # any authenticated user, no permission required
):
    return _to_out(db, config_service.get_config(db))


@router.put("/config", response_model=GlobalConfigOut)
def update_config(
    body: GlobalConfigIn,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(MANAGE_CONFIG)),
):
    try:
        config = config_service.update_config(
            db,
            updated_by_user_id=int(current_user["sub"]),
            llm_provider=body.llm_provider,
            llm_api_key=body.llm_api_key,
            cloud_provider=body.cloud_provider,
            cloud_credentials=body.cloud_credentials,
            work_directory=body.work_directory,
            data_directory=body.data_directory,
        )
    except RuntimeError as e:
        # crypto.encrypt() raises RuntimeError when CONFIG_ENCRYPTION_KEY
        # isn't set -- surfaced as a deliberate 500 with a clear message,
        # not a leaked traceback, but still a loud failure: never silently
        # drop the credential or store it in plaintext.
        raise HTTPException(500, str(e))
    return _to_out(db, config)
