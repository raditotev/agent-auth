"""Celery tasks for key rotation."""

import structlog

from agentauth.core.database import get_session_maker
from agentauth.services.crypto import CryptoService
from agentauth.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(name="agentauth.rotate_signing_keys")  # type: ignore[untyped-decorator]
def rotate_signing_keys() -> dict[str, list[str]]:
    """
    Rotate signing keys task.

    This task should be scheduled to run periodically (e.g., daily).
    It will:
    1. Mark expired keys as EXPIRED
    2. Generate new keys if no active key exists for an algorithm

    Key rotation strategy:
    - New keys generated every 30 days
    - Old keys remain valid for 60 additional days (for token verification)
    - Only ACTIVE keys are used for signing new tokens
    - ACTIVE and EXPIRED keys are published in JWKS endpoint

    Returns:
        Dict with 'expired' and 'created' key IDs
    """
    logger.info("Key rotation task started")

    # We need to run async code in a sync Celery task
    # Use asyncio to run the async function
    import asyncio

    result = asyncio.run(_rotate_keys_async())

    logger.info(
        "Key rotation task completed",
        expired_count=len(result.get("expired", [])),
        created_count=len(result.get("created", [])),
    )

    return result


async def _rotate_keys_async() -> dict[str, list[str]]:
    """
    Internal async function for key rotation.

    Returns:
        Dict with 'expired' and 'created' key IDs
    """
    session_maker = get_session_maker()

    async with session_maker() as session:
        try:
            crypto_service = CryptoService(session)
            result = await crypto_service.rotate_keys()
            await session.commit()
            return result
        except Exception as e:
            await session.rollback()
            logger.error("Key rotation failed", error=str(e), exc_info=True)
            raise
