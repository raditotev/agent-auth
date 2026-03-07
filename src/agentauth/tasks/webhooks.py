"""Celery tasks for async webhook delivery with retry (Task 4.5)."""

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

MAX_ATTEMPTS = 5
SUPPORTED_EVENTS = {
    "credential.rotated",
    "agent.suspended",
    "policy.violated",
    "delegation.revoked",
}


def _sign_payload(secret: str, payload_bytes: bytes) -> str:
    """Return HMAC-SHA256 hex signature of the payload."""
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


async def deliver_webhook(
    subscription_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """
    Deliver a webhook event to a subscription endpoint.

    Retries up to MAX_ATTEMPTS times with exponential backoff.
    Records each attempt in the delivery log.
    """
    from agentauth.core.database import get_session_maker
    from agentauth.models.webhook import WebhookDeliveryLog, WebhookSubscription
    from sqlalchemy import select
    from uuid import UUID

    session_maker = get_session_maker()

    async with session_maker() as session:
        result = await session.execute(
            select(WebhookSubscription).where(
                WebhookSubscription.id == UUID(subscription_id)
            )
        )
        subscription = result.scalar_one_or_none()
        if subscription is None or not subscription.enabled:
            return
        if event_type not in subscription.events:
            return

        payload_with_meta = {
            **payload,
            "event_type": event_type,
            "delivered_at": time.time(),
        }
        payload_bytes = json.dumps(payload_with_meta, sort_keys=True).encode()
        from agentauth.config import settings
        from agentauth.core.security import decrypt_secret
        raw_secret = decrypt_secret(subscription.secret, settings.secret_key)
        signature = _sign_payload(raw_secret, payload_bytes)

        headers = {
            "Content-Type": "application/json",
            "X-AgentAuth-Event": event_type,
            "X-AgentAuth-Signature": f"sha256={signature}",
        }

        async with httpx.AsyncClient(timeout=10.0) as http:
            for attempt in range(1, MAX_ATTEMPTS + 1):
                status_code: int | None = None
                success = False
                error_msg: str | None = None

                try:
                    resp = await http.post(
                        subscription.url,
                        content=payload_bytes,
                        headers=headers,
                    )
                    status_code = resp.status_code
                    success = 200 <= status_code < 300

                    if success:
                        logger.info(
                            "Webhook delivered",
                            subscription_id=subscription_id,
                            event_type=event_type,
                            attempt=attempt,
                            status_code=status_code,
                        )
                    else:
                        error_msg = f"HTTP {status_code}"

                except Exception as e:
                    error_msg = str(e)
                    logger.warning(
                        "Webhook delivery failed",
                        subscription_id=subscription_id,
                        event_type=event_type,
                        attempt=attempt,
                        error=error_msg,
                    )

                # Record attempt
                log_entry = WebhookDeliveryLog(
                    subscription_id=UUID(subscription_id),
                    event_type=event_type,
                    payload=payload_with_meta,
                    attempt=attempt,
                    status_code=status_code,
                    success=success,
                    error_message=error_msg,
                )
                session.add(log_entry)
                await session.commit()

                if success:
                    return

                if attempt < MAX_ATTEMPTS:
                    wait = 2 ** attempt  # exponential backoff: 2, 4, 8, 16s
                    await asyncio.sleep(wait)

    logger.error(
        "Webhook delivery exhausted retries",
        subscription_id=subscription_id,
        event_type=event_type,
    )


import asyncio  # noqa: E402


async def dispatch_event(event_type: str, payload: dict[str, Any]) -> None:
    """
    Find all subscriptions for an event type and dispatch webhook deliveries.

    Called by services after completing actions that trigger webhooks.
    """
    if event_type not in SUPPORTED_EVENTS:
        return

    from agentauth.core.database import get_session_maker
    from agentauth.models.webhook import WebhookSubscription
    from sqlalchemy import select

    session_maker = get_session_maker()
    async with session_maker() as session:
        result = await session.execute(
            select(WebhookSubscription).where(
                WebhookSubscription.enabled.is_(True)
            )
        )
        subscriptions = [s for s in result.scalars().all() if event_type in s.events]

    # Dispatch all deliveries concurrently
    tasks = [
        deliver_webhook(str(sub.id), event_type, payload)
        for sub in subscriptions
    ]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
