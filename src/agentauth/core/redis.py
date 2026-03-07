"""Redis client for caching and rate limiting."""

import json
from typing import Any

import redis.asyncio as redis
import structlog

from agentauth.config import settings

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
            logger.info("Redis client connected", url=settings.redis_url)

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
            return value
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
            return json.loads(value)
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
