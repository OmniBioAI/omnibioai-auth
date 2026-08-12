"""HIPAA Phase 1 PR2: compromised-password checking via the Have I Been
Pwned "Pwned Passwords" k-anonymity API.

Privacy mechanism (why this is safe to call with a real user password):
the password is SHA-1 hashed *locally* first -- SHA-1 here is not being
used as a security primitive protecting anything of this service's own;
it is simply the wire format the Pwned Passwords API itself is indexed
by. Only the first 5 hex characters of that digest (the "prefix") are
ever sent over the network. The API responds with every suffix in its
multi-hundred-million-entry database sharing that same 5-character
prefix (typically several hundred to a few thousand candidates) plus
each one's breach-occurrence count; the real 35-character remainder (the
"suffix") is compared against that list *locally*, never transmitted.
An observer of the network request -- including Have I Been Pwned itself
-- cannot recover the real password, or even narrow it down beyond "one
of several hundred/thousand possibilities sharing this SHA-1 prefix",
from the request alone. This is the standard, widely-deployed mechanism
for this exact problem (used by 1Password, Firefox Monitor, GitHub,
and referenced by NIST SP 800-63B) -- not a bespoke design.

Owns its own httpx client configuration, same per-module-ownership
convention `rate_limit.py`'s `_redis` / `token_revocation.py`'s
`_blacklist` already establish in this service, so tests can patch
exactly one call site.
"""
import hashlib
from dataclasses import dataclass

import httpx

from app.core.config import settings

_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


@dataclass(frozen=True)
class CompromiseCheckResult:
    performed: bool  # False if the provider could not be reached/parsed
    compromised: bool
    breach_count: int | None = None


def _sha1_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def check_compromised(password: str) -> CompromiseCheckResult:
    """Never raises. A network/parse failure returns performed=False,
    compromised=False -- the caller (password_policy.py) decides what to
    do with an unperformed check based on
    PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED; this function's own job is
    only to report, accurately, whether the check actually happened.
    """
    prefix, suffix = _sha1_prefix_suffix(password)
    try:
        response = httpx.get(
            _API_URL.format(prefix=prefix),
            timeout=settings.PASSWORD_COMPROMISE_CHECK_TIMEOUT_SECONDS,
            headers={"Add-Padding": "true"},
        )
        response.raise_for_status()
    except Exception:
        return CompromiseCheckResult(performed=False, compromised=False)

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        line_suffix, count_str = parts
        if line_suffix.strip().upper() == suffix:
            try:
                count = int(count_str.strip())
            except ValueError:
                count = None
            # The API's response-padding feature (Add-Padding: true,
            # requested above to reduce response-size side channels for
            # the *network observer* -- irrelevant to what we do with the
            # response locally) includes synthetic decoy lines with
            # count=0; a real breach entry always has count>=1.
            if count == 0:
                continue
            return CompromiseCheckResult(performed=True, compromised=True, breach_count=count)

    return CompromiseCheckResult(performed=True, compromised=False)
