"""Agent model - the sole principal identity in AgentAuth."""

import enum
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    TIMESTAMP,
    Enum,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentauth.core.database import BaseModel

if TYPE_CHECKING:
    from agentauth.models.credential import Credential


class AgentType(enum.StrEnum):
    """Type of agent."""

    ORCHESTRATOR = "orchestrator"
    AUTONOMOUS = "autonomous"
    ASSISTANT = "assistant"
    TOOL = "tool"


class TrustLevel(enum.StrEnum):
    """Trust level of agent."""

    ROOT = "root"
    DELEGATED = "delegated"
    EPHEMERAL = "ephemeral"


class AgentStatus(enum.StrEnum):
    """Status of agent."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class Agent(BaseModel):
    """
    Agent model - the sole principal identity in the system.

    Root agents have parent_agent_id=null and trust_level=root.
    They serve as the trust anchor for their subtree.
    """

    __tablename__ = "agents"

    # Self-referencing parent relationship (nullable for root agents)
    parent_agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Agent identification
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    agent_type: Mapped[AgentType] = mapped_column(
        Enum(AgentType, name="agent_type_enum", create_type=True),
        nullable=False,
        index=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    homepage_url: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    # Cryptographic identity
    public_key: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="PEM-encoded public key for verifying agent-signed requests",
    )

    # Trust and hierarchy
    trust_level: Mapped[TrustLevel] = mapped_column(
        Enum(TrustLevel, name="trust_level_enum", create_type=True),
        nullable=False,
        index=True,
    )

    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus, name="agent_status_enum", create_type=True),
        nullable=False,
        default=AgentStatus.ACTIVE,
        index=True,
    )

    max_child_depth: Mapped[int] = mapped_column(
        nullable=False,
        default=3,
        doc="Maximum levels of sub-agents this agent can spawn",
    )

    # Flexible metadata (runtime info, model version, capabilities, contact/billing refs)
    # Use 'agent_metadata' to avoid conflict with SQLAlchemy's metadata attribute
    agent_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",  # Column name in DB
        JSONB,
        nullable=True,
        default=dict,
    )

    # Deactivation timestamp
    deactivated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )

    # Relationships
    parent: Mapped["Agent | None"] = relationship(
        "Agent",
        remote_side="Agent.id",
        back_populates="children",
        foreign_keys=[parent_agent_id],
    )

    children: Mapped[list["Agent"]] = relationship(
        "Agent",
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys=[parent_agent_id],
    )

    credentials: Mapped[list["Credential"]] = relationship(
        "Credential",
        back_populates="agent",
        cascade="all, delete-orphan",
    )

    def is_root(self) -> bool:
        """Check if this is a root agent."""
        return self.parent_agent_id is None and self.trust_level == TrustLevel.ROOT

    def is_active(self) -> bool:
        """Check if agent is active."""
        return self.status == AgentStatus.ACTIVE and self.deactivated_at is None

    def deactivate(self) -> None:
        """Deactivate the agent."""
        self.status = AgentStatus.SUSPENDED
        self.deactivated_at = datetime.now(UTC)

    def __repr__(self) -> str:
        """String representation."""
        return f"<Agent {self.name} ({self.agent_type.value}) [{self.trust_level.value}]>"
