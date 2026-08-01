from sqlalchemy.orm import Session

from app.db.models import OrganizationSSOConfig


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
