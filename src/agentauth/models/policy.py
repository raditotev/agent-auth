"""Policy model for authorization rule management."""

from enum import Enum
from uuid import UUID

from sqlalchemy import UUID as SAUUID, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentauth.core.database import BaseModel


class PolicyEffect(str, Enum):
    """Whether this policy grants or denies access."""

    ALLOW = "allow"
    DENY = "deny"


class Policy(BaseModel):
    """Authorization policy — allow or deny rule evaluated against agent requests."""

    __tablename__ = "policies"

    created_by_agent_id: Mapped[UUID] = mapped_column(
        SAUUID(),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    effect: Mapped[PolicyEffect] = mapped_column(
        String(16),
        nullable=False,
        default=PolicyEffect.ALLOW,
    )
    subjects: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Agent IDs, tags, or wildcard patterns this policy applies to",
    )
    resources: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="API endpoints or service names covered by this policy",
    )
    actions: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=list,
        comment="Actions: read, write, execute, delegate, admin",
    )
    conditions: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Optional conditions: time windows, IP ranges, rate limits",
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Higher priority policies are evaluated first",
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by_agent = relationship("Agent", foreign_keys=[created_by_agent_id])
