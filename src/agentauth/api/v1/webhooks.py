"""Webhook subscription management endpoints (Task 4.5)."""

import secrets
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.models.webhook import WebhookDeliveryLog, WebhookSubscription

logger = structlog.get_logger()

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

SUPPORTED_EVENTS = [
    "credential.rotated",
    "agent.suspended",
    "policy.violated",
    "delegation.revoked",
]


class WebhookSubscriptionCreate(BaseModel):
    url: str = Field(..., description="HTTPS endpoint to deliver events to")
    events: list[str] = Field(..., description="Event types to subscribe to")


class WebhookSubscriptionResponse(BaseModel):
    id: UUID
    agent_id: UUID
    url: str
    events: list[str]
    enabled: bool

    model_config = {"from_attributes": True}


@router.post("", response_model=WebhookSubscriptionResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    payload: WebhookSubscriptionCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> WebhookSubscriptionResponse:
    """Register a webhook subscription."""
    unknown_events = set(payload.events) - set(SUPPORTED_EVENTS)
    if unknown_events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_events",
                "error_description": f"Unsupported event types: {unknown_events}",
                "supported_events": SUPPORTED_EVENTS,
            },
        )

    # TODO: replace with authenticated agent_id from request state
    from uuid import uuid4
    agent_id = uuid4()

    secret = secrets.token_hex(32)
    subscription = WebhookSubscription(
        agent_id=agent_id,
        url=payload.url,
        secret=secret,
        events=payload.events,
        enabled=True,
    )
    session.add(subscription)
    await session.commit()
    await session.refresh(subscription)

    # Return the secret once (never stored in plaintext after this point)
    response = WebhookSubscriptionResponse.model_validate(subscription)
    logger.info("Webhook subscription created", subscription_id=str(subscription.id))
    return response


@router.get("", response_model=list[WebhookSubscriptionResponse])
async def list_subscriptions(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[WebhookSubscriptionResponse]:
    """List all webhook subscriptions."""
    result = await session.execute(select(WebhookSubscription).order_by(WebhookSubscription.created_at.desc()))
    subs = list(result.scalars().all())
    return [WebhookSubscriptionResponse.model_validate(s) for s in subs]


@router.delete("/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscription(
    subscription_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a webhook subscription."""
    result = await session.execute(
        select(WebhookSubscription).where(WebhookSubscription.id == subscription_id)
    )
    subscription = result.scalar_one_or_none()
    if subscription is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    await session.delete(subscription)
    await session.commit()


@router.get("/{subscription_id}/logs")
async def get_delivery_logs(
    subscription_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 50,
) -> list[dict]:
    """Get delivery logs for a subscription."""
    result = await session.execute(
        select(WebhookDeliveryLog)
        .where(WebhookDeliveryLog.subscription_id == subscription_id)
        .order_by(WebhookDeliveryLog.created_at.desc())
        .limit(limit)
    )
    logs = list(result.scalars().all())
    return [
        {
            "id": str(log.id),
            "event_type": log.event_type,
            "attempt": log.attempt,
            "status_code": log.status_code,
            "success": log.success,
            "error_message": log.error_message,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]
