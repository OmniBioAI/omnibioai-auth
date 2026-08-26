from sqlalchemy.orm import Session

from app.db.models import OrganizationSAMLConfig, OrganizationSSOConfig


def find_org_for_email(db: Session, email: str) -> OrganizationSSOConfig | None:
    """Domain-based SSO routing lookup for GET /auth/sso/discover.

    Security: this function never queries the `users` table at all --
    structurally, not just by convention, it cannot leak whether an
    account exists for `email`. It only reveals whether some organization
    has claimed this email's domain for SSO, which is the one thing the
    discover endpoint is meant to expose.
    """
    if "@" not in email:
        return None
    domain = email.rsplit("@", 1)[-1].strip().lower()
    if not domain:
        return None

    # Small N (one config per org, orgs are not expected to number in the
    # thousands for this feature) -- filtering allowed_domains in Python
    # avoids a JSON-containment query whose syntax differs between MySQL
    # and SQLite (the latter used by this repo's own test suite).
    configs = db.query(OrganizationSSOConfig).filter(OrganizationSSOConfig.status == "active").all()
    for config in configs:
        allowed = config.allowed_domains or []
        if domain in {d.lower() for d in allowed}:
            return config
    return None


def find_enforced_org_for_email(db: Session, email: str) -> OrganizationSSOConfig | None:
    """Phase 2 PR5: returns the org's SSO config if `email`'s domain
    belongs to an org that currently enforces SSO (and has no active
    break-glass override), else None. Deliberately reuses
    find_org_for_email's exact domain-matching -- the same signal GET
    /auth/sso/discover already uses, and the only one available before a
    login attempt has proven any identity at all (there is no existing
    account/membership to consult yet for a brand-new user hitting an
    enforcing org's domain for the first time).
    """
    config = find_org_for_email(db, email)
    if config and config.enforced and config.sso_override_at is None:
        return config
    return None


def find_saml_org_for_email(db: Session, email: str) -> OrganizationSAMLConfig | None:
    """#263: SAML sibling of find_org_for_email -- identical domain-
    matching logic, against OrganizationSAMLConfig.allowed_domains
    instead. Same security property: never queries `users`, only reveals
    whether some organization has claimed this email's domain for SAML."""
    if "@" not in email:
        return None
    domain = email.rsplit("@", 1)[-1].strip().lower()
    if not domain:
        return None

    configs = db.query(OrganizationSAMLConfig).filter(OrganizationSAMLConfig.status == "active").all()
    for config in configs:
        allowed = config.allowed_domains or []
        if domain in {d.lower() for d in allowed}:
            return config
    return None


def find_enforced_saml_org_for_email(db: Session, email: str) -> OrganizationSAMLConfig | None:
    """#263: SAML sibling of find_enforced_org_for_email -- same role,
    same domain-matching signal, same "the only one available before any
    identity is proven" reasoning. One deliberate difference: no
    `config.sso_override_at is None`-style check -- OrganizationSAMLConfig
    has no break-glass override mechanism (out of scope for #263, see
    org_saml_service.py's own section comment on set_enforced), so there
    is nothing here to check beyond `enforced` itself.
    """
    config = find_saml_org_for_email(db, email)
    if config and config.enforced:
        return config
    return None
