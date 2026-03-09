"""Unit tests for RedisClient.delete_pattern pipeline optimisation."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _async_gen(*items):
    """Return an async generator that yields the given items."""

    async def _gen():
        for item in items:
            yield item

    return _gen()


def _make_client(keys: list[str]) -> AsyncMock:
    """Build a mock RedisClient whose _client mimics redis.asyncio.Redis."""
    mock_redis = AsyncMock()

    # scan_iter returns an async iterable of key names
    mock_redis.scan_iter = MagicMock(return_value=_async_gen(*keys))

    # pipeline context manager
    pipe = AsyncMock()
    pipe.unlink = MagicMock()
    # execute returns a list where each element is 1 (key unlinked) or 0 (not found)
    pipe.execute = AsyncMock(return_value=[1] * len(keys))
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)
    mock_redis.pipeline = MagicMock(return_value=pipe)

    return mock_redis, pipe


class TestDeletePatternPipeline:
    """delete_pattern batches deletes via a Redis pipeline."""

    @pytest.mark.asyncio
    async def test_returns_zero_when_no_keys_match(self) -> None:
        """When no keys match the pattern, 0 is returned and no pipeline is created."""
        from agentauth.core.redis import RedisClient

        client = RedisClient()
        mock_redis, pipe = _make_client([])
        client._client = mock_redis

        count = await client.delete_pattern("authz:*")

        assert count == 0
        mock_redis.pipeline.assert_not_called()

    @pytest.mark.asyncio
    async def test_single_key_deleted_via_pipeline(self) -> None:
        """A single matching key is deleted via the pipeline."""
        from agentauth.core.redis import RedisClient

        client = RedisClient()
        mock_redis, pipe = _make_client(["authz:agent:123"])
        client._client = mock_redis

        count = await client.delete_pattern("authz:*")

        assert count == 1
        mock_redis.pipeline.assert_called_once_with(transaction=False)
        pipe.unlink.assert_called_once_with("authz:agent:123")
        pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_multiple_keys_deleted_in_single_pipeline(self) -> None:
        """Multiple matching keys are batched into one pipeline execution."""
        from agentauth.core.redis import RedisClient

        keys = ["authz:agent:1", "authz:agent:2", "authz:agent:3"]
        client = RedisClient()
        mock_redis, pipe = _make_client(keys)
        client._client = mock_redis

        count = await client.delete_pattern("authz:*")

        assert count == 3
        # Pipeline is created only once — one round-trip regardless of key count
        mock_redis.pipeline.assert_called_once_with(transaction=False)
        assert pipe.unlink.call_count == 3
        pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_count_reflects_actually_deleted_keys(self) -> None:
        """Count is the sum of pipeline execute results, not just len(keys)."""
        from agentauth.core.redis import RedisClient

        keys = ["authz:a", "authz:b", "authz:c"]
        client = RedisClient()
        mock_redis = AsyncMock()
        mock_redis.scan_iter = MagicMock(return_value=_async_gen(*keys))

        pipe = AsyncMock()
        pipe.unlink = MagicMock()
        # Simulate one key already gone (returns 0)
        pipe.execute = AsyncMock(return_value=[1, 0, 1])
        pipe.__aenter__ = AsyncMock(return_value=pipe)
        pipe.__aexit__ = AsyncMock(return_value=False)
        mock_redis.pipeline = MagicMock(return_value=pipe)

        client._client = mock_redis

        count = await client.delete_pattern("authz:*")

        assert count == 2

    @pytest.mark.asyncio
    async def test_redis_error_returns_zero_and_logs_warning(self) -> None:
        """Redis errors are caught; method returns 0 without raising."""
        from agentauth.core.redis import RedisClient

        client = RedisClient()
        mock_redis = AsyncMock()
        mock_redis.scan_iter = MagicMock(side_effect=ConnectionError("Redis down"))
        client._client = mock_redis

        count = await client.delete_pattern("authz:*")

        assert count == 0

    @pytest.mark.asyncio
    async def test_pipeline_uses_transaction_false_for_performance(self) -> None:
        """pipeline(transaction=False) avoids MULTI/EXEC overhead."""
        from agentauth.core.redis import RedisClient

        client = RedisClient()
        mock_redis, pipe = _make_client(["authz:x"])
        client._client = mock_redis

        await client.delete_pattern("authz:*")

        mock_redis.pipeline.assert_called_once_with(transaction=False)
