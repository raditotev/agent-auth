"""Webhook subscription management endpoints (Task 4.5)."""

import secrets
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, HttpUrl, field_validator
from sqlalchemy import select

from agentauth.config import settings
from agentauth.core.database import DbSession
from agentauth.core.security import encrypt_secret
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
    url: HttpUrl = Field(..., description="HTTPS endpoint to deliver events to")
    events: list[str] = Field(..., description="Event types to subscribe to")

    @field_validator("url")
    @classmethod
    def require_https_in_production(cls, v: HttpUrl) -> HttpUrl:
        """Require HTTPS scheme in production/staging; allow HTTP in development."""
        if v.scheme != "https" and settings.environment in ("production", "staging"):
            raise ValueError(
                "Webhook URL must use HTTPS scheme. "
                "Delivering events over HTTP exposes payload and signature to interception. "
                f"Received scheme: '{v.scheme}'."
            )
        return v


class WebhookSubscriptionResponse(BaseModel):
    id: UUID
    agent_id: UUID
    url: str
    events: list[str]
    enabled: bool
    secret: str | None = None  # Raw secret returned ONCE at creation; None thereafter

    model_config = {"from_attributes": True}


@router.post("", response_model=WebhookSubscriptionResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    payload: WebhookSubscriptionCreate,
    request: Request,
    session: DbSession,
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

    agent_id = getattr(request.state, "agent_id", None)
    if agent_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "error_description": "Authentication required"},
        )

    secret = secrets.token_hex(32)
    encrypted_secret = encrypt_secret(secret, settings.secret_key)
    subscription = WebhookSubscription(
        agent_id=agent_id,
        url=str(payload.url),
        secret=encrypted_secret,
        events=payload.events,
        enabled=True,
    )
    session.add(subscription)
    await session.commit()
    await session.refresh(subscription)

    # Return the raw secret ONCE — it is stored encrypted and cannot be recovered later.
    response = WebhookSubscriptionResponse.model_validate(subscription)
    response.secret = secret
    logger.info("Webhook subscription created", subscription_id=str(subscription.id))
    return response


@router.get("", response_model=list[WebhookSubscriptionResponse])
async def list_subscriptions(
    session: DbSession,
) -> list[WebhookSubscriptionResponse]:
    """List all webhook subscriptions. The signing secret is never included in list responses."""
    result = await session.execute(select(WebhookSubscription).order_by(WebhookSubscription.created_at.desc()))
    subs = list(result.scalars().all())
    # Never expose the encrypted secret in list responses
    responses = [WebhookSubscriptionResponse.model_validate(s) for s in subs]
    for r in responses:
        r.secret = None
    return responses


@router.delete("/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscription(
    subscription_id: UUID,
    session: DbSession,
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
    session: DbSession,
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
