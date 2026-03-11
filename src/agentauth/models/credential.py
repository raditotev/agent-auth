"""Credential model - API keys and client secrets."""

import enum
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    ARRAY,
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
    from agentauth.models.agent import Agent


class CredentialType(enum.StrEnum):
    """Type of credential."""

    API_KEY = "api_key"
    CLIENT_SECRET = "client_secret"
    MTLS_CERT = "mtls_cert"
    BOOTSTRAP = "bootstrap"


class Credential(BaseModel):
    """
    Credential model for agent authentication.

    Stores hashed API keys, client secrets, and other credentials.
    The raw key value is only returned once at creation time.
    """

    __tablename__ = "credentials"

    # Agent relationship
    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Credential type
    type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, name="credential_type_enum", create_type=True),
        nullable=False,
        index=True,
    )

    # Credential value (only prefix is stored in plain text for identification)
    prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
        doc="First 8-16 characters of the key for identification in logs",
    )

    hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Argon2 hash of full key value",
    )

    # Scopes and permissions
    scopes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String),
        nullable=True,
        default=list,
    )

    # Lifecycle timestamps
    expires_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )

    last_rotated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )

    # Flexible metadata (IP allowlist, usage notes, etc.)
    # Use 'credential_metadata' to avoid conflict with SQLAlchemy's metadata attribute
    credential_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",  # Column name in DB
        JSONB,
        nullable=True,
        default=dict,
    )

    # Relationships
    agent: Mapped["Agent"] = relationship(
        "Agent",
        back_populates="credentials",
    )

    def is_valid(self) -> bool:
        """Check if credential is valid (not expired or revoked)."""
        if self.revoked_at is not None:
            return False

        return self.expires_at is None or datetime.now(UTC) <= self.expires_at

    def __repr__(self) -> str:
        """String representation."""
        return f"<Credential {self.prefix}*** ({self.type.value})>"
