"""AuditEvent model - immutable log of security-relevant events."""

import enum
from uuid import UUID

from sqlalchemy import Enum, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from agentauth.core.database import BaseModel


class ActorType(str, enum.Enum):
    """Type of actor initiating an event."""

    AGENT = "agent"
    SYSTEM = "system"


class EventOutcome(str, enum.Enum):
    """Outcome of an event."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditEvent(BaseModel):
    """
    Immutable audit log of security-relevant events.

    Records all authentication, authorization, and credential management events.
    """

    __tablename__ = "audit_events"

    # Event type (e.g., agent.created, token.issued, credential.rotated)
    event_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    # Actor information
    actor_type: Mapped[ActorType] = mapped_column(
        Enum(ActorType, name="actor_type_enum", create_type=True),
        nullable=False,
        index=True,
    )

    actor_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
        index=True,
        doc="Agent ID for agent-initiated events, null for system events",
    )

    # Target information
    target_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        doc="Type of resource affected (agent, credential, policy, delegation, token)",
    )

    target_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
        index=True,
    )

    # Action and outcome
    action: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        doc="Action performed (created, updated, deleted, issued, revoked, etc.)",
    )

    outcome: Mapped[EventOutcome] = mapped_column(
        Enum(EventOutcome, name="event_outcome_enum", create_type=True),
        nullable=False,
        index=True,
    )

    # Flexible metadata (IP, user agent, request details, parent chain, etc.)
    event_metadata: Mapped[dict | None] = mapped_column(
        "metadata",  # Column name in DB
        JSONB,
        nullable=True,
        default=dict,
    )

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<AuditEvent {self.event_type} "
            f"by {self.actor_type.value} "
            f"on {self.target_type} "
            f"[{self.outcome.value}]>"
        )
