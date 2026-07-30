import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.core import crypto
from app.db.models import GlobalConfig

# Singleton row -- webstudio has exactly one shared, admin-managed config,
# not one per user. id=1 by convention rather than a separate "is there a
# row yet" flag/table.
CONFIG_ID = 1


def get_config(db: Session) -> GlobalConfig | None:
    return db.query(GlobalConfig).filter(GlobalConfig.id == CONFIG_ID).first()


def get_or_create_config(db: Session) -> GlobalConfig:
    config = get_config(db)
    if config is None:
        config = GlobalConfig(id=CONFIG_ID)
        db.add(config)
        db.flush()
    return config


def update_config(
    db: Session,
    updated_by_user_id: int,
    *,
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
    cloud_provider: str | None = None,
    cloud_credentials: dict | None = None,
    work_directory: str | None = None,
    data_directory: str | None = None,
) -> GlobalConfig:
    """Only touches fields that were actually supplied -- None means "leave
    unchanged", so an admin can update e.g. just the work directory without
    resupplying the LLM API key every time. Raises (via crypto.encrypt) if
    CONFIG_ENCRYPTION_KEY isn't configured and a credential field was
    supplied -- never silently stores a credential in plaintext."""
    config = get_or_create_config(db)

    if llm_provider is not None:
        config.llm_provider = llm_provider
    if llm_api_key is not None:
        config.llm_api_key_encrypted = crypto.encrypt(llm_api_key)
    if cloud_provider is not None:
        config.cloud_provider = cloud_provider
    if cloud_credentials is not None:
        config.cloud_credentials_encrypted = crypto.encrypt(json.dumps(cloud_credentials))
    if work_directory is not None:
        config.work_directory = work_directory
    if data_directory is not None:
        config.data_directory = data_directory

    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = updated_by_user_id
    db.commit()
    db.refresh(config)
    return config
