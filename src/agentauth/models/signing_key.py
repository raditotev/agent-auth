"""SigningKey model for JWT signing keys."""

import enum
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import TIMESTAMP, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agentauth.core.database import BaseModel


class KeyAlgorithm(str, enum.Enum):
    """Supported signing algorithms."""

    RS256 = "RS256"  # RSA with SHA-256
    ES256 = "ES256"  # ECDSA with P-256 and SHA-256


class KeyStatus(str, enum.Enum):
    """Status of signing key."""

    PENDING = "pending"  # Generated but not yet active
    ACTIVE = "active"  # Currently being used for signing
    EXPIRED = "expired"  # Past expiration date, kept for verification only
    REVOKED = "revoked"  # Manually revoked


class SigningKey(BaseModel):
    """
    Cryptographic keys for signing JWTs.

    Keys have a lifecycle:
    - PENDING: Just generated, will become active at activation_date
    - ACTIVE: Currently used for signing new tokens
    - EXPIRED: Past expiration date, but still valid for verifying old tokens
    - REVOKED: Manually revoked, should not be used for verification

    Key rotation strategy:
    - Generate new key every 30 days
    - New key becomes active immediately (or at activation_date)
    - Old keys remain valid for 60 more days for token verification
    - Only ACTIVE keys are used for signing
    - ACTIVE and EXPIRED keys are published in JWKS endpoint
    """

    __tablename__ = "signing_keys"

    # Key identifier (used in JWT header "kid" field)
    key_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
        doc="Unique key identifier, included in JWT header",
    )

    # Algorithm
    algorithm: Mapped[KeyAlgorithm] = mapped_column(
        Enum(KeyAlgorithm, name="key_algorithm_enum", create_type=True),
        nullable=False,
        index=True,
    )

    # Private key (PEM-encoded, encrypted at rest in production)
    private_key_pem: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="PEM-encoded private key (should be encrypted at rest)",
    )

    # Public key (PEM-encoded)
    public_key_pem: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="PEM-encoded public key",
    )

    # Status
    status: Mapped[KeyStatus] = mapped_column(
        Enum(KeyStatus, name="key_status_enum", create_type=True),
        nullable=False,
        default=KeyStatus.PENDING,
        index=True,
    )

    # Lifecycle dates
    activation_date: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        index=True,
        doc="Date when key becomes active for signing",
    )

    expiration_date: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        index=True,
        doc="Date when key expires (stops being used for signing, but still valid for verification)",
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
        doc="Date when key was manually revoked",
    )

    def is_active(self) -> bool:
        """Check if key is currently active for signing."""
        now = datetime.now(UTC)
        return (
            self.status == KeyStatus.ACTIVE
            and self.activation_date <= now < self.expiration_date
            and self.revoked_at is None
        )

    def is_valid_for_verification(self) -> bool:
        """Check if key can be used for token verification."""
        # Can verify tokens signed with ACTIVE or EXPIRED keys
        # REVOKED keys should not be used
        return self.status in (KeyStatus.ACTIVE, KeyStatus.EXPIRED) and self.revoked_at is None

    def should_be_in_jwks(self) -> bool:
        """Check if key should be published in JWKS endpoint."""
        return self.is_valid_for_verification()

    def mark_expired(self) -> None:
        """Mark key as expired."""
        if self.status == KeyStatus.ACTIVE:
            self.status = KeyStatus.EXPIRED

    def revoke(self) -> None:
        """Revoke the key."""
        self.status = KeyStatus.REVOKED
        self.revoked_at = datetime.now(UTC)

    def __repr__(self) -> str:
        """String representation."""
        return f"<SigningKey {self.key_id} ({self.algorithm.value}) [{self.status.value}]>"
