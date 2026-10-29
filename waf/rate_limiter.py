"""
Redis-backed rate limiter with sliding-window counters, strikes, and bans.

All Redis operations use short timeouts and fail open (skip rate limiting)
when Redis is unavailable, so the inspection pipeline continues to protect
traffic even without state.
"""

from __future__ import annotations

import logging
import time
import uuid

import redis.asyncio as aioredis

logger = logging.getLogger("waf.rate_limiter")

# ---------------------------------------------------------------------------
# Lua script: atomic sliding-window rate check
# ---------------------------------------------------------------------------
#
# KEYS[1] = rate:{ip}
# ARGV[1] = now (float seconds)
# ARGV[2] = window_sec
# ARGV[3] = limit (max requests in window)
# ARGV[4] = unique member id
#
# Returns the count of requests in the current window AFTER adding the new one.
# The caller decides whether to allow or deny based on the returned count.

SLIDING_WINDOW_LUA = """
local key      = KEYS[1]
local now      = tonumber(ARGV[1])
local window   = tonumber(ARGV[2])
local limit    = tonumber(ARGV[3])
local member   = ARGV[4]

-- Remove entries older than the window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count current entries BEFORE adding the new one
local count = redis.call('ZCARD', key)

-- If already at or over the limit, don't add – just return the count
if count >= limit then
    redis.call('EXPIRE', key, math.ceil(window))
    return count
end

-- Under the limit – add the request
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window))

return count + 1
"""

# Redis command timeout (seconds) – keeps the hot path fast
_REDIS_TIMEOUT = 0.5


class RateLimiter:
    """Sliding-window rate limiter with strike accumulation and IP banning."""

    def __init__(
        self,
        redis_url: str,
        rate_limit_rps: int,
        window_sec: int,
        strike_threshold: int,
        ban_ttl_sec: int,
    ):
        self._redis_url = redis_url
        self._limit = rate_limit_rps * window_sec  # total allowed in window
        self._window_sec = window_sec
        self._strike_threshold = strike_threshold
        self._ban_ttl_sec = ban_ttl_sec
        self._redis: aioredis.Redis | None = None
        self._lua_sha: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """Connect to Redis and load the Lua script."""
        try:
            self._redis = aioredis.from_url(
                self._redis_url,
                socket_timeout=_REDIS_TIMEOUT,
                socket_connect_timeout=_REDIS_TIMEOUT,
                decode_responses=True,
            )
            await self._redis.ping()
            self._lua_sha = await self._redis.script_load(SLIDING_WINDOW_LUA)
            logger.info("Redis connected, Lua script loaded (SHA=%s)", self._lua_sha)
        except Exception:
            logger.exception("Failed to connect to Redis – rate limiting disabled")
            self._redis = None

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def is_banned(self, ip: str) -> bool:
        """Return True if *ip* has an active ban."""
        if not self._redis:
            return False
        try:
            return bool(await self._redis.exists(f"ban:{ip}"))
        except Exception:
            logger.warning("Redis error checking ban for %s", ip, exc_info=True)
            return False

    async def check_rate(self, ip: str) -> tuple[bool, int]:
        """Check the sliding-window rate limit for *ip*.

        Returns ``(allowed, current_count)``.  On Redis failure the
        request is allowed (fail-open).
        """
        if not self._redis or not self._lua_sha:
            return True, 0

        try:
            now = time.time()
            member = f"{now}:{uuid.uuid4().hex[:8]}"
            count = await self._redis.evalsha(
                self._lua_sha,
                1,
                f"rate:{ip}",
                str(now),
                str(self._window_sec),
                str(self._limit),
                member,
            )
            count = int(count)
            if count > self._limit:
                await self._add_strike(ip)
                return False, count
            return True, count
        except Exception:
            logger.warning("Redis error on rate check for %s", ip, exc_info=True)
            return True, 0

    async def record_detection_strike(self, ip: str) -> None:
        """Increment strikes for *ip* after a detection rule blocks a request."""
        if not self._redis:
            return
        try:
            await self._add_strike(ip)
        except Exception:
            logger.warning("Redis error recording strike for %s", ip, exc_info=True)

    async def ping(self) -> bool:
        """Return True if Redis is reachable."""
        if not self._redis:
            return False
        try:
            return await self._redis.ping()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _add_strike(self, ip: str) -> None:
        """Increment the strike counter and auto-ban when threshold is reached."""
        key = f"strikes:{ip}"
        strikes = await self._redis.incr(key)
        # Strike TTL = 2× ban TTL so history decays
        await self._redis.expire(key, self._ban_ttl_sec * 2)

        if int(strikes) >= self._strike_threshold:
            await self._redis.setex(
                f"ban:{ip}",
                self._ban_ttl_sec,
                "1",
            )
            logger.warning(
                "IP %s banned for %d seconds (strikes=%s)",
                ip, self._ban_ttl_sec, strikes,
            )
