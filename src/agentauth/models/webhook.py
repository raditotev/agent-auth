"""Webhook subscription model (Task 4.5)."""

from uuid import UUID

from sqlalchemy import UUID as SAUUID
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentauth.core.database import BaseModel


class WebhookSubscription(BaseModel):
    """Represents a webhook endpoint registered to receive auth events."""

    __tablename__ = "webhook_subscriptions"

    agent_id: Mapped[UUID] = mapped_column(
        SAUUID(),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        comment="Target URL for webhook delivery",
    )
    secret: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="HMAC-SHA256 signing secret",
    )
    events: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=list,
        comment="Event types to deliver: credential.rotated, agent.suspended, etc.",
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    agent = relationship("Agent", foreign_keys=[agent_id])


class WebhookDeliveryLog(BaseModel):
    """Immutable log of each webhook delivery attempt."""

    __tablename__ = "webhook_delivery_logs"

    subscription_id: Mapped[UUID] = mapped_column(
        SAUUID(),
        ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    subscription = relationship("WebhookSubscription", foreign_keys=[subscription_id])
