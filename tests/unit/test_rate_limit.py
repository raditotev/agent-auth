"""Unit tests for sliding window rate limiter boundary conditions."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_redis(*, zcard: int = 0) -> AsyncMock:
    """Create a mock Redis client with configurable current request count."""
    redis = AsyncMock()
    redis.zremrangebyscore = AsyncMock(return_value=0)
    redis.zcard = AsyncMock(return_value=zcard)
    redis.zadd = AsyncMock(return_value=1)
    redis.expire = AsyncMock(return_value=True)
    return redis


def _make_settings(*, api_limit: int = 100, token_limit: int = 20, window: int = 60) -> MagicMock:
    settings = MagicMock()
    settings.rate_limit_api_requests = api_limit
    settings.rate_limit_token_requests = token_limit
    settings.rate_limit_window_seconds = window
    return settings


class TestRateLimitAllowed:
    """Requests within the limit are allowed."""

    @pytest.mark.asyncio
    async def test_first_request_is_allowed(self) -> None:
        """First request (count=0) is always allowed."""
        from agentauth.core.rate_limit import check_rate_limit

        redis = _make_redis(zcard=0)
        settings = _make_settings(api_limit=100)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is True
        redis.zadd.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_at_limit_minus_one_is_allowed(self) -> None:
        """The last request before the limit is reached is allowed."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 10
        redis = _make_redis(zcard=limit - 1)  # 9 existing → count<limit
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is True


class TestRateLimitRejected:
    """Requests at or above the limit are rejected."""

    @pytest.mark.asyncio
    async def test_request_at_exact_limit_is_rejected(self) -> None:
        """Request when count == limit is rejected (>= check)."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 10
        redis = _make_redis(zcard=limit)  # already at limit
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is False
        redis.zadd.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_above_limit_is_rejected(self) -> None:
        """Request when count > limit is rejected."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 10
        redis = _make_redis(zcard=limit + 5)
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, _ = await check_rate_limit("agent:test", "api")

        assert allowed is False


class TestRateLimitHeaders:
    """Rate limit response headers are correct."""

    @pytest.mark.asyncio
    async def test_allowed_response_has_correct_headers(self) -> None:
        """Allowed response includes X-RateLimit-Limit and X-RateLimit-Remaining."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 50
        current = 10
        redis = _make_redis(zcard=current)
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            _, headers = await check_rate_limit("agent:test", "api")

        assert headers["X-RateLimit-Limit"] == str(limit)
        # Remaining = limit - current - 1 (this request)
        assert headers["X-RateLimit-Remaining"] == str(limit - current - 1)
        assert "X-RateLimit-Reset" in headers

    @pytest.mark.asyncio
    async def test_rejected_response_includes_retry_after(self) -> None:
        """Rejected response includes Retry-After header."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 10
        window = 60
        redis = _make_redis(zcard=limit)
        settings = _make_settings(api_limit=limit, window=window)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is False
        assert "Retry-After" in headers
        assert headers["Retry-After"] == str(window)

    @pytest.mark.asyncio
    async def test_remaining_is_zero_at_limit_minus_one(self) -> None:
        """When count is limit-1 the remaining drops to 0 (this is the last slot)."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 5
        redis = _make_redis(zcard=limit - 1)
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is True
        assert headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_remaining_never_goes_negative(self) -> None:
        """X-RateLimit-Remaining is clamped to 0 even when count > limit."""
        from agentauth.core.rate_limit import check_rate_limit

        limit = 5
        redis = _make_redis(zcard=limit + 10)  # Way over
        settings = _make_settings(api_limit=limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            _, headers = await check_rate_limit("agent:test", "api")

        remaining = int(headers["X-RateLimit-Remaining"])
        assert remaining == 0


class TestEndpointTypeLimits:
    """token vs api endpoint_type uses different limit settings."""

    @pytest.mark.asyncio
    async def test_token_endpoint_uses_token_limit(self) -> None:
        """endpoint_type='token' applies the stricter token rate limit."""
        from agentauth.core.rate_limit import check_rate_limit

        token_limit = 5
        api_limit = 1000
        # At count=5: should be rejected for token but allowed for api
        redis = _make_redis(zcard=token_limit)
        settings = _make_settings(api_limit=api_limit, token_limit=token_limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "token")

        assert allowed is False
        assert headers["X-RateLimit-Limit"] == str(token_limit)

    @pytest.mark.asyncio
    async def test_api_endpoint_uses_api_limit(self) -> None:
        """endpoint_type='api' applies the lenient api rate limit."""
        from agentauth.core.rate_limit import check_rate_limit

        token_limit = 5
        api_limit = 1000
        # At count=5: rejected for token, allowed for api
        redis = _make_redis(zcard=5)
        settings = _make_settings(api_limit=api_limit, token_limit=token_limit)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is True
        assert headers["X-RateLimit-Limit"] == str(api_limit)

    @pytest.mark.asyncio
    async def test_token_and_api_use_different_redis_keys(self) -> None:
        """Different endpoint types produce different Redis keys."""
        from agentauth.core.rate_limit import check_rate_limit

        redis = _make_redis(zcard=0)
        settings = _make_settings()

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            await check_rate_limit("agent:abc", "token")
            await check_rate_limit("agent:abc", "api")

        # zremrangebyscore called twice with different keys
        calls = redis.zremrangebyscore.call_args_list
        assert len(calls) == 2
        keys = {c[0][0] for c in calls}
        assert "ratelimit:token:agent:abc" in keys
        assert "ratelimit:api:agent:abc" in keys


class TestRateLimitRedisFailure:
    """Redis failures cause fail-open behaviour."""

    @pytest.mark.asyncio
    async def test_redis_error_fails_open(self) -> None:
        """When Redis is unavailable, requests are allowed (fail-open)."""
        from agentauth.core.rate_limit import check_rate_limit

        redis = AsyncMock()
        redis.zremrangebyscore = AsyncMock(side_effect=ConnectionError("Redis down"))

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", _make_settings()),
        ):
            allowed, headers = await check_rate_limit("agent:test", "api")

        assert allowed is True
        assert headers["X-RateLimit-Limit"] == "unknown"
        assert headers["X-RateLimit-Remaining"] == "unknown"
        assert headers["X-RateLimit-Reset"] == "unknown"

    @pytest.mark.asyncio
    async def test_redis_error_returns_unknown_headers(self) -> None:
        """Redis failure headers are all set to 'unknown'."""
        from agentauth.core.rate_limit import check_rate_limit

        redis = AsyncMock()
        redis.zremrangebyscore = AsyncMock(side_effect=Exception("unexpected"))

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", _make_settings()),
        ):
            _, headers = await check_rate_limit("agent:test", "token")

        for key in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
            assert headers[key] == "unknown"


class TestRateLimitWindowExpiry:
    """Old entries are removed from the window before counting."""

    @pytest.mark.asyncio
    async def test_zremrangebyscore_called_to_clean_window(self) -> None:
        """check_rate_limit cleans stale entries via zremrangebyscore."""
        from agentauth.core.rate_limit import check_rate_limit

        redis = _make_redis(zcard=0)
        settings = _make_settings(window=60)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            await check_rate_limit("agent:test", "api")

        redis.zremrangebyscore.assert_called_once()
        # The second arg should be "-inf" (remove everything before window_start)
        call_args = redis.zremrangebyscore.call_args[0]
        assert call_args[1] == "-inf"

    @pytest.mark.asyncio
    async def test_key_ttl_set_to_double_window(self) -> None:
        """Redis key TTL is set to 2× the window for auto-expiry."""
        from agentauth.core.rate_limit import check_rate_limit

        window = 60
        redis = _make_redis(zcard=0)
        settings = _make_settings(window=window)

        with (
            patch("agentauth.core.redis.get_redis_client", return_value=redis),
            patch("agentauth.config.settings", settings),
        ):
            await check_rate_limit("agent:test", "api")

        redis.expire.assert_called_once()
        _, ttl_arg = redis.expire.call_args[0]
        assert ttl_arg == window * 2
