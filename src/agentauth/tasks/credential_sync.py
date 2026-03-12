"""Celery task to flush credential last_used_at timestamps from Redis to Postgres."""

from datetime import datetime
from uuid import UUID

import structlog
from sqlalchemy import update

from agentauth.core.database import get_session_maker
from agentauth.core.redis import RedisClient, get_redis_client
from agentauth.models.credential import Credential
from agentauth.tasks.celery_app import celery_app

logger = structlog.get_logger()

REDIS_KEY_PREFIX = "cred_last_used:"


@celery_app.task(name="agentauth.flush_credential_last_used")  # type: ignore[untyped-decorator]
def flush_credential_last_used() -> dict[str, int]:
    """Flush ``cred_last_used:*`` timestamps from Redis into Postgres.

    Scans Redis for deferred last_used_at writes, bulk-updates the
    credentials table, then removes the processed keys.

    Returns:
        Dict with ``flushed`` count of updated credentials.
    """
    import asyncio

    result = asyncio.run(_flush_last_used_async())

    logger.info("flush_credential_last_used completed", **result)
    return result


async def _flush_last_used_async(
    redis_client: RedisClient | None = None,
) -> dict[str, int]:
    """Read pending last_used_at values from Redis and write them to the DB."""
    if redis_client is None:
        redis_client = get_redis_client()
        await redis_client.connect()

    keys = await redis_client.scan_keys(f"{REDIS_KEY_PREFIX}*")
    if not keys:
        return {"flushed": 0}

    # Collect credential_id → timestamp pairs
    updates: dict[UUID, datetime] = {}
    for key in keys:
        value = await redis_client.get(key)
        if value is None:
            continue
        cred_id_str = key[len(REDIS_KEY_PREFIX) :]
        try:
            cred_id = UUID(cred_id_str)
            ts = datetime.fromisoformat(value)
            # Keep only the latest timestamp per credential
            if cred_id not in updates or ts > updates[cred_id]:
                updates[cred_id] = ts
        except (ValueError, TypeError) as exc:
            logger.warning("invalid_cred_last_used_key", key=key, error=str(exc))
            continue

    if not updates:
        # Keys existed but none had valid data — clean them up
        for key in keys:
            await redis_client.delete(key)
        return {"flushed": 0}

    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            # Bulk update each credential's last_used_at
            for cred_id, ts in updates.items():
                stmt = update(Credential).where(Credential.id == cred_id).values(last_used_at=ts)
                await session.execute(stmt)
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("flush_credential_last_used failed", error=str(e), exc_info=True)
            raise

    # Delete processed Redis keys only after successful DB commit
    for key in keys:
        await redis_client.delete(key)

    return {"flushed": len(updates)}
