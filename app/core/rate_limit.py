"""HIPAA Phase 1 PR1: atomic Redis primitives for login abuse protection.
Reused, not duplicated, by HIPAA Phase 3's MFA/TOTP challenge throttle
(`app/services/mfa_throttle_service.py`) -- every function here is generic
over its `fail_key`/`lock_key` strings and (for the Redis path) its
window/max-attempts/lockout arguments, so a second caller with its own
policy and its own key namespace needs no changes to this module beyond
the optional `fallback_*` overrides on `record_attempt` (see its
docstring) that let that caller's in-process fallback use its own,
independently-tuned thresholds instead of silently inheriting the login
control's.

Owns its own Redis client (`_redis`), same per-module-ownership convention
`token_revocation._blacklist` and `routes_auth._pub` already establish in
this service -- each Redis-backed concern gets exactly one client, not a
shared global.

Every counter here is a fixed-window counter (INCR, EXPIRE-once-on-first-
increment) plus a separate boolean "lock" key with its own TTL, combined
into one atomic Lua script (`_INCR_AND_LOCK_SCRIPT`) so a burst of
concurrent requests against the same key can never race a plain
read-then-increment-then-write sequence into overshooting or under-
counting -- Redis executes the whole script as a single, uninterruptible
operation per call.

Redis-unavailable handling is NOT the fail-open policy `token_revocation.py`
documents for its own blacklist check (see that module's docstring for why
fail-open is correct *there*). Fail-open here would silently disable the
one control this PR exists to add, exactly when sustained attack traffic
might itself be the thing straining shared infra. Fail-closed globally
would instead make a Redis outage a total login outage -- worse than the
control being temporarily degraded. So: on any Redis error, every function
below falls back to `_InProcessFallback`, a small bounded in-memory
counter using its own, deliberately tighter, `RATE_LIMIT_FALLBACK_*`
settings. This fallback is NOT shared across service instances -- a
multi-replica deployment gets weaker (per-instance) protection during a
Redis outage, not zero protection. That tradeoff is deliberate and
documented, not an oversight (see docs/security-auth-rate-limiting.md).
"""
import os
import threading
import time
from dataclasses import dataclass

import redis as _redis_sync
from prometheus_client import Counter

from app.core.config import settings

_redis = _redis_sync.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"),
    decode_responses=True,
    socket_connect_timeout=1,
    socket_timeout=1,
)

# No labels -- this is a binary "was the primary backend reachable just
# now" signal for operators, not a per-key/per-dimension breakdown.
RATE_LIMIT_BACKEND_DEGRADED = Counter(
    "auth_rate_limit_backend_degraded_total",
    "Login rate-limit checks that fell back to in-process state because Redis was unreachable",
)

# KEYS[1] = fail counter key, KEYS[2] = lock flag key
# ARGV[1] = window_seconds, ARGV[2] = max_attempts, ARGV[3] = lockout_seconds
# Returns {locked (0/1), newly_locked (0/1), count}.
#
# The already-locked branch deliberately does not increment the fail
# counter further -- once locked, additional attempts are rejected by the
# caller before they'd even reach `authenticate_user`/bcrypt, so this
# branch mainly exists to serialize a race where multiple requests already
# in flight all cross the threshold at once: the first to execute inside
# Redis wins "newly_locked", every other concurrent one sees the lock the
# first one just set and reports locked-but-not-newly.
_INCR_AND_LOCK_SCRIPT = """
if redis.call('EXISTS', KEYS[2]) == 1 then
  local count = tonumber(redis.call('GET', KEYS[1]) or '0')
  return {1, 0, count}
end
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
if count >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'EX', ARGV[3])
  return {1, 1, count}
end
return {0, 0, count}
"""

# KEYS[1] = strike counter key, ARGV[1] = strike_ttl_seconds
# Returns the post-increment strike count.
_STRIKE_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""


@dataclass(frozen=True)
class RateLimitResult:
    locked: bool
    newly_locked: bool
    count: int


class _InProcessFallback:
    """Bounded, per-process, degraded-mode-only counter used while Redis
    is unreachable. Not a general rate-limiter -- see module docstring.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, tuple[float, int]] = {}  # key -> (window_start, count)
        self._locks: dict[str, float] = {}  # key -> expires_at

    def _evict_if_full(self):
        max_keys = settings.RATE_LIMIT_FALLBACK_MAX_KEYS
        if len(self._counters) + len(self._locks) > max_keys:
            # Degraded mode only -- drop everything rather than build an
            # LRU for a code path that should only ever be active for the
            # duration of a Redis outage.
            self._counters.clear()
            self._locks.clear()

    def record_attempt(
        self,
        fail_key: str,
        lock_key: str,
        window_seconds: int | None = None,
        max_attempts: int | None = None,
    ) -> RateLimitResult:
        """`window_seconds`/`max_attempts` default to the login control's
        own RATE_LIMIT_FALLBACK_* settings when omitted -- every existing
        caller (login_throttle_service.py) is unaffected. A caller with
        its own, independently-tuned fallback policy (e.g.
        mfa_throttle_service.py -- see that module and
        MFA_RATE_LIMIT_FALLBACK_* in config.py for why MFA's fallback is
        deliberately tighter than login's) passes them explicitly instead
        of silently inheriting login's thresholds."""
        now = time.monotonic()
        window = window_seconds if window_seconds is not None else settings.RATE_LIMIT_FALLBACK_WINDOW_SECONDS
        max_attempts = max_attempts if max_attempts is not None else settings.RATE_LIMIT_FALLBACK_MAX_ATTEMPTS
        with self._lock:
            expires_at = self._locks.get(lock_key)
            if expires_at is not None and expires_at > now:
                window_start, count = self._counters.get(fail_key, (now, 0))
                return RateLimitResult(locked=True, newly_locked=False, count=count)
            if expires_at is not None:
                del self._locks[lock_key]

            self._evict_if_full()
            window_start, count = self._counters.get(fail_key, (now, 0))
            if now - window_start > window:
                window_start, count = now, 0
            count += 1
            self._counters[fail_key] = (window_start, count)

            if count >= max_attempts:
                self._locks[lock_key] = now + window
                return RateLimitResult(locked=True, newly_locked=True, count=count)
            return RateLimitResult(locked=False, newly_locked=False, count=count)

    def is_locked(self, lock_key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            expires_at = self._locks.get(lock_key)
            if expires_at is not None and expires_at > now:
                return True, int(expires_at - now)
            return False, 0

    def clear(self, *keys: str):
        with self._lock:
            for key in keys:
                self._counters.pop(key, None)
                self._locks.pop(key, None)


_fallback = _InProcessFallback()


def record_attempt(
    fail_key: str,
    lock_key: str,
    window_seconds: int,
    max_attempts: int,
    lockout_seconds: int,
    fallback_window_seconds: int | None = None,
    fallback_max_attempts: int | None = None,
) -> RateLimitResult:
    """Atomically increments `fail_key` and, if `max_attempts` is reached
    within `window_seconds`, sets `lock_key` for `lockout_seconds`. Falls
    back to a tighter in-process counter on Redis error -- see module
    docstring. `fallback_window_seconds`/`fallback_max_attempts` let a
    caller with its own fallback policy (see _InProcessFallback.record_attempt)
    override the login control's default RATE_LIMIT_FALLBACK_* settings;
    omitted by every caller that wants those defaults, unaffected.
    """
    try:
        locked, newly_locked, count = _redis.eval(
            _INCR_AND_LOCK_SCRIPT, 2, fail_key, lock_key, window_seconds, max_attempts, lockout_seconds
        )
        return RateLimitResult(locked=bool(locked), newly_locked=bool(newly_locked), count=int(count))
    except Exception:
        RATE_LIMIT_BACKEND_DEGRADED.inc()
        return _fallback.record_attempt(fail_key, lock_key, fallback_window_seconds, fallback_max_attempts)


def is_locked(lock_key: str) -> tuple[bool, int]:
    """Read-only peek: is `lock_key` currently set, and for how many more
    seconds. Used before any credential verification runs, so a caller can
    reject an already-throttled request without touching bcrypt/the DB.
    """
    try:
        ttl = _redis.ttl(lock_key)
        if ttl is not None and ttl > 0:
            return True, ttl
        return False, 0
    except Exception:
        RATE_LIMIT_BACKEND_DEGRADED.inc()
        return _fallback.is_locked(lock_key)


def clear(*keys: str) -> None:
    """Best-effort reset of the given fail/lock keys -- called on a
    successful login. Never raises: a failure to clear just means the
    counters expire naturally via their own TTL instead of being reset
    early, which is a minor UX nuisance, not a security issue.
    """
    try:
        if keys:
            _redis.delete(*keys)
    except Exception:
        pass
    try:
        _fallback.clear(*keys)
    except Exception:
        pass


def bump_strikes(strike_key: str, strike_ttl_seconds: int) -> int:
    """Atomically increments the progressive-escalation strike counter for
    an account and returns the new count. Falls back to a simple (still
    correct, just not cross-process-atomic) increment on Redis error --
    strikes only affect lockout *duration*, not whether a lockout happens,
    so a rare off-by-one race here has no security impact.
    """
    try:
        return int(_redis.eval(_STRIKE_SCRIPT, 1, strike_key, strike_ttl_seconds))
    except Exception:
        RATE_LIMIT_BACKEND_DEGRADED.inc()
        now = time.monotonic()
        with _fallback._lock:
            window_start, count = _fallback._counters.get(strike_key, (now, 0))
            if now - window_start > strike_ttl_seconds:
                window_start, count = now, 0
            count += 1
            _fallback._counters[strike_key] = (window_start, count)
            return count


def set_lock_ttl(lock_key: str, ttl_seconds: int) -> None:
    """Extends an already-set lock key's TTL -- used to apply the
    progressive-escalation multiplier after `record_attempt` has already
    set the base lockout duration. Best-effort/non-raising for the same
    reason as `clear` above.
    """
    try:
        _redis.expire(lock_key, ttl_seconds)
    except Exception:
        with _fallback._lock:
            if lock_key in _fallback._locks:
                _fallback._locks[lock_key] = time.monotonic() + ttl_seconds
