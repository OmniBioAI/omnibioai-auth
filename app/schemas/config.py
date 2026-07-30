from pydantic import BaseModel


class GlobalConfigIn(BaseModel):
    """All fields optional and independently updatable -- omitting a field
    means "leave unchanged", not "clear it" (see config_service.update_config).
    llm_api_key/cloud_credentials are write-only: accepted here, never
    echoed back by GlobalConfigOut below."""
    llm_provider: str | None = None
    llm_api_key: str | None = None
    cloud_provider: str | None = None
    cloud_credentials: dict | None = None
    work_directory: str | None = None
    data_directory: str | None = None


class GlobalConfigOut(BaseModel):
    """No credential fields, ever, regardless of caller role -- has_* flags
    only. This is the ONLY response shape for reading config; there is no
    "admin gets the real values" variant."""
    llm_provider: str | None
    has_llm_api_key: bool
    cloud_provider: str | None
    has_cloud_credentials: bool
    work_directory: str | None
    data_directory: str | None
    updated_at: str | None
    updated_by_email: str | None
