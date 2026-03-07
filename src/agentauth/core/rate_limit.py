"""Sliding window rate limiting using Redis (Task 4.4)."""

from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

# Default limits (requests per window)
# Token endpoints are stricter; management API is more lenient.
RATE_LIMIT_TOKEN_REQUESTS = 30   # per minute
RATE_LIMIT_API_REQUESTS = 300    # per minute
RATE_LIMIT_WINDOW_SECONDS = 60


async def check_rate_limit(
    identifier: str,
    endpoint_type: str = "api",
) -> tuple[bool, dict[str, str]]:
    """
    Check whether a request is within the rate limit using a sliding window.

    Uses Redis sorted sets: each request is stored with its timestamp as score.
    The window is the last RATE_LIMIT_WINDOW_SECONDS seconds.

    Args:
        identifier: Unique key for the client (e.g. "agent:{agent_id}")
        endpoint_type: "token" (strict) or "api" (lenient)

    Returns:
        (allowed, headers) where headers contain X-RateLimit-* values.
    """
    try:
        from agentauth.core.redis import get_redis_client
        redis_client = get_redis_client()

        limit = RATE_LIMIT_TOKEN_REQUESTS if endpoint_type == "token" else RATE_LIMIT_API_REQUESTS
        now = datetime.now(UTC)
        now_ts = now.timestamp()
        window_start = now_ts - RATE_LIMIT_WINDOW_SECONDS

        redis_key = f"ratelimit:{endpoint_type}:{identifier}"

        # Remove entries outside the window
        await redis_client.client.zremrangebyscore(redis_key, "-inf", window_start)

        # Count requests in the current window
        current_count = await redis_client.client.zcard(redis_key)

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, limit - current_count - 1)),
            "X-RateLimit-Reset": str(int(now_ts + RATE_LIMIT_WINDOW_SECONDS)),
        }

        if current_count >= limit:
            headers["Retry-After"] = str(RATE_LIMIT_WINDOW_SECONDS)
            logger.warning(
                "Rate limit exceeded",
                identifier=identifier,
                endpoint_type=endpoint_type,
                count=current_count,
                limit=limit,
            )
            return False, headers

        # Record this request
        await redis_client.client.zadd(redis_key, {f"{now_ts}:{id(object())}": now_ts})
        # Set key TTL to auto-expire old entries
        await redis_client.client.expire(redis_key, RATE_LIMIT_WINDOW_SECONDS * 2)

        return True, headers

    except Exception as e:
        # Redis failure: fail open (allow the request, log the error)
        logger.error("Rate limit check failed — allowing request", error=str(e))
        return True, {
            "X-RateLimit-Limit": "unknown",
            "X-RateLimit-Remaining": "unknown",
            "X-RateLimit-Reset": "unknown",
        }
