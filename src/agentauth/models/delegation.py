"""Delegation model — authorization chain between agents."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import UUID as SAUUID
from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentauth.core.database import BaseModel


class Delegation(BaseModel):
    """Represents an authorization delegation from one agent to another.

    Scope attenuation is enforced: a delegation can only grant a subset of
    what the delegator currently holds.
    """

    __tablename__ = "delegations"

    delegator_agent_id: Mapped[UUID] = mapped_column(
        SAUUID(),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    delegate_agent_id: Mapped[UUID] = mapped_column(
        SAUUID(),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        default=list,
        comment="Scopes granted — must be subset of delegator's effective scopes",
    )
    constraints: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Time bounds, resource restrictions, max re-delegation depth",
    )
    chain_depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="0 = directly from a root agent, increments with each hop",
    )
    max_chain_depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        comment="Maximum allowed re-delegation depth from this delegation",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    delegator_agent = relationship("Agent", foreign_keys=[delegator_agent_id])
    delegate_agent = relationship("Agent", foreign_keys=[delegate_agent_id])

    def is_active(self) -> bool:
        """Return True if delegation is not revoked and not expired."""
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or datetime.now(UTC) <= self.expires_at
