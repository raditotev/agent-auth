"""Sliding window rate limiting using Redis sorted sets + Lua script."""

import secrets
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

# Lua script that performs the full sliding-window check in a single round trip.
# Returns a 3-element array: [allowed (0/1), current_count, _unused].
RATE_LIMIT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_ttl = tonumber(ARGV[4])
local member = ARGV[5]

-- Remove old entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
-- Count current
local count = redis.call('ZCARD', key)
-- Check limit
if count >= limit then
    return {0, count, -1}
end
-- Add and expire
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window_ttl)
return {1, count + 1, 0}
"""


async def check_rate_limit(
    identifier: str,
    endpoint_type: str = "api",
) -> tuple[bool, dict[str, str]]:
    """
    Check whether a request is within the rate limit using a sliding window.

    Uses a single Redis Lua script to atomically clean, count, and record
    the request in one round trip.

    Args:
        identifier: Unique key for the client (e.g. "agent:{agent_id}")
        endpoint_type: "token" (strict) or "api" (lenient)

    Returns:
        (allowed, headers) where headers contain X-RateLimit-* values.
    """
    try:
        from agentauth.config import settings
        from agentauth.core.redis import get_redis_client

        redis_client = get_redis_client()

        if endpoint_type == "token":
            limit = settings.rate_limit_token_requests
        elif endpoint_type == "bootstrap":
            limit = settings.rate_limit_bootstrap_requests
        else:
            limit = settings.rate_limit_api_requests
        window = settings.rate_limit_window_seconds
        now = datetime.now(UTC)
        now_ts = now.timestamp()
        window_start = now_ts - window

        redis_key = f"ratelimit:{endpoint_type}:{identifier}"
        member = f"{now_ts}:{secrets.token_hex(8)}"

        result = await redis_client.eval_script(
            RATE_LIMIT_LUA,
            keys=[redis_key],
            args=[
                str(now_ts),
                str(window_start),
                str(limit),
                str(window * 2),
                member,
            ],
        )

        allowed_flag, current_count = int(result[0]), int(result[1])
        allowed = allowed_flag == 1

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, limit - current_count)),
            "X-RateLimit-Reset": str(int(now_ts + window)),
        }

        if not allowed:
            headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count))
            headers["Retry-After"] = str(window)
            logger.warning(
                "Rate limit exceeded",
                identifier=identifier,
                endpoint_type=endpoint_type,
                count=current_count,
                limit=limit,
            )

        return allowed, headers

    except Exception as e:
        # Redis failure: fail open (allow the request, log the error)
        logger.error("Rate limit check failed — allowing request", error=str(e))
        return True, {
            "X-RateLimit-Limit": "unknown",
            "X-RateLimit-Remaining": "unknown",
            "X-RateLimit-Reset": "unknown",
        }
