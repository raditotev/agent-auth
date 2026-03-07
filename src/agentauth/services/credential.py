"""Credential service for API key lifecycle management."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.exceptions import CredentialError, NotFoundError
from agentauth.core.security import (
    generate_api_key,
    get_key_prefix,
    hash_secret,
    verify_secret,
)
from agentauth.models.credential import Credential, CredentialType
from agentauth.services.audit import AuditService

logger = structlog.get_logger()


class CredentialService:
    """Service for managing agent credentials."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize credential service."""
        self.session = session
        self.audit = AuditService(session)

    async def create_credential(
        self,
        agent_id: UUID,
        credential_type: CredentialType = CredentialType.API_KEY,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        actor_id: UUID | None = None,
    ) -> tuple[Credential, str]:
        """
        Create a new credential for an agent.

        Args:
            agent_id: Agent ID
            credential_type: Type of credential
            scopes: Permission scopes
            expires_at: Expiration time (null = never)
            metadata: Additional metadata
            actor_id: ID of actor creating credential (for audit)

        Returns:
            Tuple of (Credential object, raw API key)
        """
        # Generate secure random API key
        raw_key = generate_api_key(length=32)

        # Extract prefix for identification
        prefix = get_key_prefix(raw_key, length=8)

        # Hash the key for storage
        key_hash = hash_secret(raw_key)

        # Create credential record
        credential = Credential(
            agent_id=agent_id,
            type=credential_type,
            prefix=prefix,
            hash=key_hash,
            scopes=scopes or [],
            expires_at=expires_at,
            credential_metadata=metadata or {},
        )

        self.session.add(credential)
        await self.session.flush()

        # Record audit event
        await self.audit.record_credential_created(
            credential_id=credential.id,
            agent_id=agent_id,
            credential_type=credential_type.value,
            actor_id=actor_id,
            metadata={
                "scopes": scopes or [],
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

        logger.info(
            "credential_created",
            credential_id=str(credential.id),
            agent_id=str(agent_id),
            type=credential_type.value,
            prefix=prefix,
        )

        return credential, raw_key

    async def get_credential(self, credential_id: UUID) -> Credential:
        """
        Get credential by ID.

        Args:
            credential_id: Credential ID

        Returns:
            Credential object

        Raises:
            NotFoundError: If credential not found
        """
        result = await self.session.execute(
            select(Credential).where(Credential.id == credential_id)
        )
        credential = result.scalar_one_or_none()

        if not credential:
            raise NotFoundError(
                f"Credential not found: {credential_id}",
                detail={"credential_id": str(credential_id)},
            )

        return credential

    async def get_credentials_by_prefix(self, prefix: str) -> list[Credential]:
        """
        Get all credentials matching a prefix.

        Multiple credentials can share the same 8-character prefix (collision).
        Callers must verify the hash against each candidate.

        Args:
            prefix: Key prefix

        Returns:
            List of matching Credential objects
        """
        result = await self.session.execute(
            select(Credential).where(Credential.prefix == prefix)
        )
        return list(result.scalars().all())

    async def list_credentials(
        self,
        agent_id: UUID | None = None,
        include_revoked: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Credential]:
        """
        List credentials.

        Args:
            agent_id: Filter by agent ID
            include_revoked: Include revoked credentials
            limit: Maximum number to return
            offset: Offset for pagination

        Returns:
            List of credentials
        """
        query = select(Credential)

        if agent_id:
            query = query.where(Credential.agent_id == agent_id)

        if not include_revoked:
            query = query.where(Credential.revoked_at.is_(None))

        query = query.order_by(Credential.created_at.desc())
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def verify_credential(self, raw_key: str) -> Credential | None:
        """
        Verify an API key and return associated credential.

        Handles prefix collisions by checking the hash against all
        credentials sharing the same prefix.

        Args:
            raw_key: Raw API key to verify

        Returns:
            Credential object if valid, None otherwise
        """
        # Extract prefix to find candidate credentials
        prefix = get_key_prefix(raw_key, length=8)

        candidates = await self.get_credentials_by_prefix(prefix)

        if not candidates:
            logger.warning("credential_not_found", prefix=prefix)
            return None

        # Check each candidate for a hash match
        for credential in candidates:
            # Skip invalid credentials early
            if not credential.is_valid():
                continue

            if verify_secret(credential.hash, raw_key):
                # Update last_used_at
                credential.last_used_at = datetime.now(UTC)
                await self.session.flush()

                logger.info(
                    "credential_verified",
                    credential_id=str(credential.id),
                    agent_id=str(credential.agent_id),
                    prefix=prefix,
                )
                return credential

        logger.warning("credential_verification_failed", prefix=prefix)
        return None

    async def revoke_credential(
        self,
        credential_id: UUID,
        actor_id: UUID | None = None,
    ) -> Credential:
        """
        Revoke a credential.

        Args:
            credential_id: Credential ID
            actor_id: ID of actor revoking credential (for audit)

        Returns:
            Revoked credential

        Raises:
            NotFoundError: If credential not found
            CredentialError: If credential already revoked
        """
        credential = await self.get_credential(credential_id)

        if credential.revoked_at is not None:
            raise CredentialError(
                "Credential already revoked",
                detail={
                    "credential_id": str(credential_id),
                    "revoked_at": credential.revoked_at.isoformat(),
                },
            )

        # Revoke credential
        credential.revoked_at = datetime.now(UTC)
        await self.session.flush()

        # Record audit event
        await self.audit.record_credential_revoked(
            credential_id=credential.id,
            agent_id=credential.agent_id,
            actor_id=actor_id,
        )

        logger.info(
            "credential_revoked",
            credential_id=str(credential.id),
            agent_id=str(credential.agent_id),
            prefix=credential.prefix,
        )

        return credential

    async def rotate_credential(
        self,
        credential_id: UUID,
        actor_id: UUID | None = None,
    ) -> tuple[Credential, Credential, str]:
        """
        Rotate a credential (revoke old, create new).

        Args:
            credential_id: ID of credential to rotate
            actor_id: ID of actor rotating credential (for audit)

        Returns:
            Tuple of (old credential, new credential, raw new key)

        Raises:
            NotFoundError: If credential not found
        """
        old_credential = await self.get_credential(credential_id)

        # Create new credential with same properties
        new_credential, raw_key = await self.create_credential(
            agent_id=old_credential.agent_id,
            credential_type=old_credential.type,
            scopes=old_credential.scopes,
            expires_at=old_credential.expires_at,
            metadata=old_credential.credential_metadata,
            actor_id=actor_id,
        )

        # Revoke old credential
        old_credential.revoked_at = datetime.now(UTC)
        old_credential.last_rotated_at = datetime.now(UTC)
        await self.session.flush()

        # Record audit event
        await self.audit.record_credential_rotated(
            old_credential_id=old_credential.id,
            new_credential_id=new_credential.id,
            agent_id=old_credential.agent_id,
            actor_id=actor_id,
        )

        logger.info(
            "credential_rotated",
            old_credential_id=str(old_credential.id),
            new_credential_id=str(new_credential.id),
            agent_id=str(old_credential.agent_id),
        )

        return old_credential, new_credential, raw_key
