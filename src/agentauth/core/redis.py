"""Redis client for caching and rate limiting."""

import json
from typing import Any, cast

import redis.asyncio as redis
import structlog

from agentauth.config import settings
from agentauth.core.url_utils import mask_url as _mask_url

logger = structlog.get_logger()


class RedisClient:
    """Redis client wrapper for caching and rate limiting operations."""

    def __init__(self) -> None:
        """Initialize Redis client."""
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis server."""
        if self._client is None:
            self._client = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info("Redis client connected", url=_mask_url(settings.redis_url))

    async def disconnect(self) -> None:
        """Disconnect from Redis server."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("Redis client disconnected")

    async def get(self, key: str) -> str | None:
        """
        Get value from Redis.

        Args:
            key: Cache key

        Returns:
            Value if exists, None otherwise
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None

        try:
            value = await self._client.get(key)
            return cast(str | None, value)
        except Exception as e:
            logger.warning("Redis GET failed", key=key, error=str(e))
            return None

    async def set(
        self,
        key: str,
        value: str,
        ex: int | None = None,
    ) -> bool:
        """
        Set value in Redis.

        Args:
            key: Cache key
            value: Value to store
            ex: Expiration time in seconds

        Returns:
            True if successful
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None

        try:
            await self._client.set(key, value, ex=ex)
            return True
        except Exception as e:
            logger.warning("Redis SET failed", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete key from Redis.

        Args:
            key: Cache key

        Returns:
            True if successful
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None

        try:
            await self._client.delete(key)
            return True
        except Exception as e:
            logger.warning("Redis DELETE failed", key=key, error=str(e))
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in Redis.

        Args:
            key: Cache key

        Returns:
            True if key exists
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None

        try:
            result = await self._client.exists(key)
            return bool(result)
        except Exception as e:
            logger.warning("Redis EXISTS failed", key=key, error=str(e))
            return False

    async def get_json(self, key: str) -> dict[str, Any] | None:
        """
        Get JSON value from Redis.

        Args:
            key: Cache key

        Returns:
            Parsed JSON dict if exists, None otherwise
        """
        value = await self.get(key)
        if value is None:
            return None

        try:
            return cast(dict[str, Any] | None, json.loads(value))
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse JSON from Redis", key=key, error=str(e))
            return None

    async def set_json(
        self,
        key: str,
        value: dict[str, Any],
        ex: int | None = None,
    ) -> bool:
        """
        Set JSON value in Redis.

        Args:
            key: Cache key
            value: Dict to store as JSON
            ex: Expiration time in seconds

        Returns:
            True if successful
        """
        try:
            json_str = json.dumps(value)
            return await self.set(key, json_str, ex=ex)
        except (TypeError, ValueError) as e:
            logger.warning("Failed to serialize JSON for Redis", key=key, error=str(e))
            return False

    async def zremrangebyscore(
        self, key: str, min_score: str | float, max_score: str | float
    ) -> int:
        """Remove sorted set members with scores between min and max."""
        if self._client is None:
            await self.connect()
        assert self._client is not None
        try:
            return int(await self._client.zremrangebyscore(key, min_score, max_score))
        except Exception as e:
            logger.warning("Redis ZREMRANGEBYSCORE failed", key=key, error=str(e))
            return 0

    async def zcard(self, key: str) -> int:
        """Return the number of members in a sorted set."""
        if self._client is None:
            await self.connect()
        assert self._client is not None
        try:
            return int(await self._client.zcard(key))
        except Exception as e:
            logger.warning("Redis ZCARD failed", key=key, error=str(e))
            return 0

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        """Add members to a sorted set."""
        if self._client is None:
            await self.connect()
        assert self._client is not None
        try:
            return int(await self._client.zadd(key, mapping))
        except Exception as e:
            logger.warning("Redis ZADD failed", key=key, error=str(e))
            return 0

    async def expire(self, key: str, seconds: int) -> bool:
        """Set a key's time to live in seconds."""
        if self._client is None:
            await self.connect()
        assert self._client is not None
        try:
            return bool(await self._client.expire(key, seconds))
        except Exception as e:
            logger.warning("Redis EXPIRE failed", key=key, error=str(e))
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a glob pattern. Returns count of deleted keys.

        Uses SCAN to collect all matching keys and then deletes them in a single
        pipeline call using UNLINK (non-blocking) to reduce round-trips from O(n)
        to O(1) network calls.
        """
        if self._client is None:
            await self.connect()
        assert self._client is not None
        try:
            keys = [key async for key in self._client.scan_iter(pattern)]
            if not keys:
                return 0
            async with self._client.pipeline(transaction=False) as pipe:
                for key in keys:
                    pipe.unlink(key)
                results = await pipe.execute()
            return sum(results)
        except Exception as e:
            logger.warning("Redis DELETE_PATTERN failed", pattern=pattern, error=str(e))
            return 0


# Global Redis client instance
_redis_client: RedisClient | None = None


def get_redis_client() -> RedisClient:
    """
    Get global Redis client instance.

    Returns:
        RedisClient instance
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient()
    return _redis_client
