"""Unit tests for credential service."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.exceptions import CredentialError, NotFoundError
from agentauth.core.security import verify_secret
from agentauth.models.agent import Agent
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService


@pytest.mark.asyncio
class TestCredentialService:
    """Tests for CredentialService."""

    async def test_create_credential_success(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test creating a credential."""
        service = CredentialService(db_session)

        credential, raw_key = await service.create_credential(
            agent_id=root_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["read", "write"],
        )

        # Check credential properties
        assert credential.agent_id == root_agent.id
        assert credential.type == CredentialType.API_KEY
        assert len(credential.prefix) == 8
        assert credential.scopes == ["read", "write"]
        assert credential.is_valid() is True

        # Check raw key
        assert len(raw_key) == 32
        assert raw_key.isalnum()

        # Verify hash
        assert verify_secret(credential.hash, raw_key) is True

        # Raw key should not be stored
        assert raw_key not in credential.hash
        assert credential.prefix == raw_key[:8]

    async def test_create_credential_with_expiration(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test creating a credential with expiration."""
        service = CredentialService(db_session)
        expires_at = datetime.now(UTC) + timedelta(days=30)

        credential, raw_key = await service.create_credential(
            agent_id=root_agent.id,
            expires_at=expires_at,
        )

        assert credential.expires_at is not None
        assert credential.expires_at == expires_at

    async def test_create_bootstrap_credential(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test creating a bootstrap credential."""
        service = CredentialService(db_session)

        credential, raw_key = await service.create_credential(
            agent_id=root_agent.id,
            credential_type=CredentialType.BOOTSTRAP,
        )

        assert credential.type == CredentialType.BOOTSTRAP
        assert credential.is_valid() is True

    async def test_get_credential_success(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test getting a credential by ID."""
        service = CredentialService(db_session)

        credential, _ = await service.create_credential(agent_id=root_agent.id)

        retrieved = await service.get_credential(credential.id)
        assert retrieved.id == credential.id
        assert retrieved.agent_id == root_agent.id

    async def test_get_credential_not_found(self, db_session: AsyncSession) -> None:
        """Test getting a non-existent credential."""
        service = CredentialService(db_session)

        from uuid_extensions import uuid7

        with pytest.raises(NotFoundError):
            await service.get_credential(uuid7())

    async def test_get_credentials_by_prefix(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test getting credentials by prefix."""
        service = CredentialService(db_session)

        credential, raw_key = await service.create_credential(agent_id=root_agent.id)

        results = await service.get_credentials_by_prefix(credential.prefix)
        assert len(results) >= 1
        assert any(r.id == credential.id for r in results)

    async def test_list_credentials_by_agent(
        self, db_session: AsyncSession, root_agent: Agent, child_agent: Agent
    ) -> None:
        """Test listing credentials for a specific agent."""
        service = CredentialService(db_session)

        # Create credentials for different agents
        cred1, _ = await service.create_credential(agent_id=root_agent.id)
        cred2, _ = await service.create_credential(agent_id=root_agent.id)
        cred3, _ = await service.create_credential(agent_id=child_agent.id)

        # List root agent credentials
        root_creds = await service.list_credentials(agent_id=root_agent.id)
        assert len(root_creds) == 2
        assert cred1.id in [c.id for c in root_creds]
        assert cred2.id in [c.id for c in root_creds]

        # List child agent credentials
        child_creds = await service.list_credentials(agent_id=child_agent.id)
        assert len(child_creds) == 1
        assert child_creds[0].id == cred3.id

    async def test_list_credentials_exclude_revoked(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test listing credentials excludes revoked by default."""
        service = CredentialService(db_session)

        # Create and revoke a credential
        cred1, _ = await service.create_credential(agent_id=root_agent.id)
        cred2, _ = await service.create_credential(agent_id=root_agent.id)
        await service.revoke_credential(cred1.id)

        # List without revoked
        creds = await service.list_credentials(agent_id=root_agent.id)
        assert len(creds) == 1
        assert creds[0].id == cred2.id

        # List with revoked
        all_creds = await service.list_credentials(agent_id=root_agent.id, include_revoked=True)
        assert len(all_creds) == 2

    async def test_verify_credential_success(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test verifying a valid credential."""
        service = CredentialService(db_session)

        credential, raw_key = await service.create_credential(agent_id=root_agent.id)

        verified = await service.verify_credential(raw_key)
        assert verified is not None
        assert verified.id == credential.id
        assert verified.agent_id == root_agent.id

        # last_used_at is now deferred to Redis, not set on the model directly
        # (see test_credential_sync.py for Redis/flush tests)

    async def test_verify_credential_invalid_key(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test verifying with wrong key."""
        service = CredentialService(db_session)

        await service.create_credential(agent_id=root_agent.id)

        # Try to verify with wrong key
        verified = await service.verify_credential("wrongkey123456789012345678901234")
        assert verified is None

    async def test_verify_credential_revoked(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test verifying a revoked credential."""
        service = CredentialService(db_session)

        credential, raw_key = await service.create_credential(agent_id=root_agent.id)

        # Revoke the credential
        await service.revoke_credential(credential.id)

        # Should not verify
        verified = await service.verify_credential(raw_key)
        assert verified is None

    async def test_verify_credential_expired(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test verifying an expired credential."""
        service = CredentialService(db_session)

        # Create credential that's already expired
        expires_at = datetime.now(UTC) - timedelta(days=1)
        credential, raw_key = await service.create_credential(
            agent_id=root_agent.id,
            expires_at=expires_at,
        )

        # Should not verify
        verified = await service.verify_credential(raw_key)
        assert verified is None

    async def test_revoke_credential_success(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test revoking a credential."""
        service = CredentialService(db_session)

        credential, _ = await service.create_credential(agent_id=root_agent.id)

        revoked = await service.revoke_credential(credential.id)
        assert revoked.revoked_at is not None
        assert revoked.is_valid() is False

    async def test_revoke_credential_already_revoked(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test revoking an already revoked credential."""
        service = CredentialService(db_session)

        credential, _ = await service.create_credential(agent_id=root_agent.id)
        await service.revoke_credential(credential.id)

        # Try to revoke again
        with pytest.raises(CredentialError):
            await service.revoke_credential(credential.id)

    async def test_rotate_credential_success(
        self, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test rotating a credential."""
        service = CredentialService(db_session)

        old_credential, old_key = await service.create_credential(
            agent_id=root_agent.id,
            scopes=["read", "write"],
        )

        old_cred, new_cred, new_key = await service.rotate_credential(old_credential.id)

        # Old credential should be revoked
        assert old_cred.revoked_at is not None
        assert old_cred.last_rotated_at is not None
        assert old_cred.is_valid() is False

        # New credential should be valid with same properties
        assert new_cred.agent_id == old_credential.agent_id
        assert new_cred.type == old_credential.type
        assert new_cred.scopes == old_credential.scopes
        assert new_cred.is_valid() is True

        # Keys should be different
        assert new_key != old_key
        assert new_cred.prefix != old_credential.prefix

        # Old key should not verify
        old_verified = await service.verify_credential(old_key)
        assert old_verified is None

        # New key should verify
        new_verified = await service.verify_credential(new_key)
        assert new_verified is not None
        assert new_verified.id == new_cred.id

    async def test_credential_scopes(self, db_session: AsyncSession, root_agent: Agent) -> None:
        """Test credential with scopes."""
        service = CredentialService(db_session)

        credential, _ = await service.create_credential(
            agent_id=root_agent.id,
            scopes=["files.read", "files.write", "email.send"],
        )

        assert credential.scopes == ["files.read", "files.write", "email.send"]

    async def test_credential_metadata(self, db_session: AsyncSession, root_agent: Agent) -> None:
        """Test credential with metadata."""
        service = CredentialService(db_session)

        metadata = {
            "ip_allowlist": ["192.168.1.0/24", "10.0.0.0/8"],
            "usage_note": "Production API key",
        }

        credential, _ = await service.create_credential(
            agent_id=root_agent.id,
            metadata=metadata,
        )

        assert credential.credential_metadata == metadata
