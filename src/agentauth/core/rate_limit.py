"""Sliding window rate limiting using Redis (Task 4.4)."""

import secrets
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()


async def check_rate_limit(
    identifier: str,
    endpoint_type: str = "api",
) -> tuple[bool, dict[str, str]]:
    """
    Check whether a request is within the rate limit using a sliding window.

    Uses Redis sorted sets: each request is stored with its timestamp as score.
    Limits and window duration are loaded from application settings.

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

        # Remove entries outside the window
        await redis_client.zremrangebyscore(redis_key, "-inf", window_start)

        # Count requests in the current window
        current_count = await redis_client.zcard(redis_key)

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, limit - current_count - 1)),
            "X-RateLimit-Reset": str(int(now_ts + window)),
        }

        if current_count >= limit:
            headers["Retry-After"] = str(window)
            logger.warning(
                "Rate limit exceeded",
                identifier=identifier,
                endpoint_type=endpoint_type,
                count=current_count,
                limit=limit,
            )
            return False, headers

        # Record this request with a stable unique member key
        await redis_client.zadd(redis_key, {f"{now_ts}:{secrets.token_hex(8)}": now_ts})
        # Set key TTL to auto-expire old entries
        await redis_client.expire(redis_key, window * 2)

        return True, headers

    except Exception as e:
        # Redis failure: fail open (allow the request, log the error)
        logger.error("Rate limit check failed — allowing request", error=str(e))
        return True, {
            "X-RateLimit-Limit": "unknown",
            "X-RateLimit-Remaining": "unknown",
            "X-RateLimit-Reset": "unknown",
        }
