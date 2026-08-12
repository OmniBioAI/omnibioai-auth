"""HIPAA Phase 1 PR2: local-password security policy.

Single entry point (`validate_new_password`) called from exactly one
place today -- `POST /auth/register` in `app/api/routes_auth.py` -- the
only user-facing local-password-creation endpoint this service has.
See that route for why: discovery (PR2's own report) found no
password-change, password-reset, admin-creates-user, or invitation/
activation endpoint anywhere in this codebase to also wire this into.
`init_admin.py`'s one-time bootstrap-admin creation is deliberately NOT
routed through this function either -- see that module's own comment for
why (gating service *startup* on a network-dependent check is a worse
failure mode than an operator setting a weak bootstrap password once,
and it already defaults to a random 192-bit token when unset).

Policy, in evaluation order (cheapest/most available first):
  1. length (PASSWORD_MIN_LENGTH / PASSWORD_MAX_LENGTH) -- no network,
     no character-class rules. Length is the primary strength lever;
     see docs/security-password-policy.md for why complexity rules
     (mandatory uppercase/number/symbol) are deliberately not imposed.
  2. password == the account's own email -- free, obviously unsafe.
  3. local common-password blocklist (common_passwords.py) -- no
     network, always available, small.
  4. HIBP k-anonymity compromised-password check
     (compromised_password.py) -- the comprehensive check, but the only
     one with an external dependency; see that module and
     PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED in config.py for exactly what
     happens if it can't be reached.

Every rejection raises the same `PasswordPolicyError` with the same
generic message, regardless of which rule failed or why -- callers must
not construct a more specific message from `reason`. That field exists
for logging/metrics only, never for the HTTP response, so a rejected
registration cannot be used to fingerprint which specific rule (let
alone which specific breach) a candidate password tripped.
"""
from dataclasses import dataclass

from prometheus_client import Counter

from app.core import compromised_password
from app.core.common_passwords import COMMON_PASSWORDS
from app.core.config import settings

# Bounded label cardinality (5 fixed reasons) -- never the password or
# any derivative of it.
PASSWORD_REJECTED_TOTAL = Counter(
    "password_policy_rejected_total",
    "Local-password creation attempts rejected by policy, by reason",
    ["reason"],
)
PASSWORD_COMPROMISE_CHECK_ERRORS_TOTAL = Counter(
    "password_compromise_check_errors_total",
    "Compromised-password provider calls that could not be completed (timeout/error)",
)


@dataclass
class PasswordPolicyError(Exception):
    reason: str  # internal only -- see module docstring

    def __str__(self) -> str:
        return "This password cannot be used because it does not meet the security requirements."


def validate_new_password(password: str, email: str | None = None) -> None:
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        PASSWORD_REJECTED_TOTAL.labels(reason="too_short").inc()
        raise PasswordPolicyError("too_short")

    if len(password) > settings.PASSWORD_MAX_LENGTH:
        PASSWORD_REJECTED_TOTAL.labels(reason="too_long").inc()
        raise PasswordPolicyError("too_long")

    if email and password.strip().lower() == email.strip().lower():
        PASSWORD_REJECTED_TOTAL.labels(reason="matches_email").inc()
        raise PasswordPolicyError("matches_email")

    if password.lower() in COMMON_PASSWORDS:
        PASSWORD_REJECTED_TOTAL.labels(reason="common_password").inc()
        raise PasswordPolicyError("common_password")

    if settings.PASSWORD_COMPROMISE_CHECK_ENABLED:
        result = compromised_password.check_compromised(password)
        if not result.performed:
            PASSWORD_COMPROMISE_CHECK_ERRORS_TOTAL.inc()
            if settings.PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED:
                PASSWORD_REJECTED_TOTAL.labels(reason="check_unavailable").inc()
                raise PasswordPolicyError("check_unavailable")
            # Fail open (default): local checks above already ran and
            # passed, so this password is at minimum policy-length and
            # not in the local blocklist -- proceeding without the
            # network-backed check, not without any check at all.
        elif result.compromised:
            PASSWORD_REJECTED_TOTAL.labels(reason="compromised").inc()
            raise PasswordPolicyError("compromised")
