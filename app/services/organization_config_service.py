"""M14 (design audit gap #4's "organisation-scoped BYOK provider-key
service"): an organization can store its own Claude/OpenAI key, used
instead of the platform's own when the public API answers that
organization's questions. The underlying organization_config table has
existed since the multi-tenant schema migration with nobody reading or
writing it -- this module is its first real consumer.

M15 exposed the storage endpoint through the public gateway's own
/v1/provider-keys/{provider} path. M16 adds the one remaining piece
this module needs for actual routing: reveal_provider_key(), which
decrypts a stored key for a single internal, service-to-service call --
see app/api/routes_organization_config.py's reveal endpoint and its own
docstring for the access-control story. The Claude/OpenAI client calls,
token accounting, and llm.tokens.* usage events themselves live in
omnibioai-api-gateway/omnibioai-rag, not here.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.core import crypto
from app.db.models import OrganizationConfig
from app.services import audit_service
from app.services.audit_service import AuditEventType

# One provider/key pair per organization at a time -- the same shape
# omnibioai-auth's own GlobalConfig already uses for the platform-wide
# LLM credential (config_service.py), not a new multi-provider-per-org
# design. Setting a key for a different provider replaces whichever one
# was previously configured, exactly like PUT /auth/config with a new
# llm_provider does there.
SUPPORTED_PROVIDERS = {"claude", "openai"}


def get_organization_config(db: Session, organization_id: int) -> OrganizationConfig | None:
    return db.query(OrganizationConfig).filter_by(organization_id=organization_id).first()


def _get_or_create(db: Session, organization_id: int) -> OrganizationConfig:
    config = get_organization_config(db, organization_id)
    if config is None:
        config = OrganizationConfig(organization_id=organization_id)
        db.add(config)
        db.flush()
    return config


def set_provider_key(
    db: Session, organization_id: int, provider: str, api_key: str, updated_by_user_id: int,
) -> OrganizationConfig:
    """Raises ValueError for an unsupported provider name, and (via
    crypto.encrypt) RuntimeError if CONFIG_ENCRYPTION_KEY isn't
    configured -- never silently stores a credential in plaintext."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}")

    config = _get_or_create(db, organization_id)
    config.llm_provider = provider
    config.llm_api_key_encrypted = crypto.encrypt(api_key)
    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = updated_by_user_id
    db.flush()
    # Never the key itself or its ciphertext in audit metadata -- the
    # same "name/scope only" rule apikey_service.create_api_key's own
    # audit entry follows.
    audit_service.log_event(
        db, AuditEventType.PROVIDER_KEY_SET, actor_user_id=updated_by_user_id,
        organization_id=organization_id, resource_type="organization_config", resource_id=config.id,
        after_state={"provider": provider}, metadata={"provider": provider},
        commit=False,
    )
    db.commit()
    db.refresh(config)
    return config


def reveal_provider_key(db: Session, organization_id: int, provider: str) -> str | None:
    """Decrypts and returns the organization's stored key for `provider`,
    or None if nothing is configured for that provider (including the
    case where some *other* provider is configured instead -- same "only
    one slot" semantics clear_provider_key already established). Raises
    ValueError for an unsupported provider name, and (via crypto.decrypt)
    RuntimeError if CONFIG_ENCRYPTION_KEY isn't configured.

    Callers must never persist, log, or echo the return value anywhere
    beyond the single outbound provider API call it exists for -- see
    this module's own docstring and routes_organization_config.py's
    reveal endpoint for the access-control story around who may call
    this at all. Deliberately not audit-logged: a reveal happens on
    every routed /v1/literature/answers call using BYOK, the same
    per-use (not per-lifecycle-change) frequency apikey_service.
    exchange_api_key already leaves unaudited for the identical reason.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}")

    config = get_organization_config(db, organization_id)
    if config is None or config.llm_provider != provider or not config.llm_api_key_encrypted:
        return None
    return crypto.decrypt(config.llm_api_key_encrypted)


def clear_provider_key(
    db: Session, organization_id: int, provider: str, updated_by_user_id: int,
) -> OrganizationConfig | None:
    """Returns None (the route turns this into 404) if the organization
    has no config row at all, or its currently-configured provider
    doesn't match `provider` -- there is only one slot, so "clear
    openai's key" when the org actually has a claude key configured
    isn't a no-op clear of the wrong thing, it's simply nothing to do.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}")

    config = get_organization_config(db, organization_id)
    if config is None or config.llm_provider != provider:
        return None

    config.llm_provider = None
    config.llm_api_key_encrypted = None
    config.updated_at = datetime.utcnow()
    config.updated_by_user_id = updated_by_user_id
    db.flush()
    audit_service.log_event(
        db, AuditEventType.PROVIDER_KEY_CLEARED, actor_user_id=updated_by_user_id,
        organization_id=organization_id, resource_type="organization_config", resource_id=config.id,
        before_state={"provider": provider}, metadata={"provider": provider},
        commit=False,
    )
    db.commit()
    db.refresh(config)
    return config
