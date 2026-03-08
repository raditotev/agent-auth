"""Integration tests for credential API endpoints."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService


@pytest.mark.asyncio
class TestCredentialAPI:
    """Integration tests for credential endpoints."""

    async def test_create_credential_success(self, client: AsyncClient, root_agent: Agent) -> None:
        """Test POST /api/v1/credentials creates a credential."""
        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "api_key",
                "scopes": ["read", "write"],
            },
        )

        assert response.status_code == 201
        data = response.json()

        # Check response structure
        assert "credential" in data
        assert "raw_key" in data
        assert "message" in data

        # Check credential data
        credential = data["credential"]
        assert credential["agent_id"] == str(root_agent.id)
        assert credential["type"] == "api_key"
        assert credential["scopes"] == ["read", "write"]
        assert len(credential["prefix"]) == 8
        assert credential["is_valid"] is True

        # Check raw key
        raw_key = data["raw_key"]
        assert len(raw_key) == 32
        assert raw_key.isalnum()
        assert raw_key.startswith(credential["prefix"])

    async def test_create_credential_with_expiration(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """Test creating credential with expiration time."""
        expires_at = (datetime.now(UTC) + timedelta(days=30)).isoformat()

        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "api_key",
                "expires_at": expires_at,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["credential"]["expires_at"] is not None

    async def test_create_bootstrap_credential(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """Test creating bootstrap credential for self-registration."""
        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "bootstrap",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["credential"]["type"] == "bootstrap"

    async def test_create_credential_with_metadata(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """Test creating credential with metadata."""
        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "api_key",
                "metadata": {
                    "ip_allowlist": ["192.168.1.0/24"],
                    "note": "Test credential",
                },
            },
        )

        assert response.status_code == 201
        data = response.json()
        metadata = data["credential"]["metadata"]
        assert "ip_allowlist" in metadata
        assert metadata["note"] == "Test credential"

    async def test_list_credentials_success(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test GET /api/v1/credentials lists credentials."""
        # Create some credentials
        service = CredentialService(db_session)
        cred1, _ = await service.create_credential(agent_id=root_agent.id)
        cred2, _ = await service.create_credential(agent_id=root_agent.id)

        response = await client.get("/api/v1/credentials")

        assert response.status_code == 200
        data = response.json()

        assert "data" in data
        assert "meta" in data
        assert len(data["data"]) == 2

        # Check that keys are masked (only prefix shown)
        for credential in data["data"]:
            assert len(credential["prefix"]) == 8
            assert "hash" not in credential  # Hash should not be exposed

    async def test_list_credentials_filter_by_agent(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Test listing credentials filtered by agent."""
        service = CredentialService(db_session)
        await service.create_credential(agent_id=root_agent.id)
        await service.create_credential(agent_id=root_agent.id)
        await service.create_credential(agent_id=child_agent.id)

        # List root agent credentials
        response = await client.get(f"/api/v1/credentials?agent_id={str(root_agent.id)}")

        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 2

    async def test_list_credentials_exclude_revoked(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test listing credentials excludes revoked by default."""
        service = CredentialService(db_session)
        cred1, _ = await service.create_credential(agent_id=root_agent.id)
        cred2, _ = await service.create_credential(agent_id=root_agent.id)

        # Revoke one
        await service.revoke_credential(cred1.id)

        # List without revoked
        response = await client.get("/api/v1/credentials")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 1

        # List with revoked
        response = await client.get("/api/v1/credentials?include_revoked=true")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 2

    async def test_get_credential_success(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test GET /api/v1/credentials/{id} returns credential details."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=root_agent.id)

        response = await client.get(f"/api/v1/credentials/{str(credential.id)}")

        assert response.status_code == 200
        data = response.json()

        assert "data" in data
        assert data["data"]["id"] == str(credential.id)
        assert data["data"]["agent_id"] == str(root_agent.id)
        assert data["data"]["prefix"] == credential.prefix

    async def test_get_credential_not_found(self, client: AsyncClient) -> None:
        """Test getting a non-existent credential."""
        from uuid_extensions import uuid7

        response = await client.get(f"/api/v1/credentials/{str(uuid7())}")

        assert response.status_code == 404
        assert "detail" in response.json()

    async def test_revoke_credential_success(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test DELETE /api/v1/credentials/{id} revokes credential."""
        service = CredentialService(db_session)
        credential, raw_key = await service.create_credential(agent_id=root_agent.id)

        # Revoke
        response = await client.delete(f"/api/v1/credentials/{str(credential.id)}")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["revoked_at"] is not None
        assert data["data"]["is_valid"] is False

        # Verify the key no longer works
        verified = await service.verify_credential(raw_key)
        assert verified is None

    async def test_revoke_credential_already_revoked(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test revoking an already revoked credential."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=root_agent.id)

        # Revoke once
        await service.revoke_credential(credential.id)

        # Try to revoke again
        response = await client.delete(f"/api/v1/credentials/{str(credential.id)}")

        assert response.status_code == 400
        assert "already revoked" in response.json()["detail"].lower()

    async def test_rotate_credential_success(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test POST /api/v1/credentials/{id}/rotate rotates credential."""
        service = CredentialService(db_session)
        old_credential, old_key = await service.create_credential(
            agent_id=root_agent.id,
            scopes=["read", "write"],
        )

        # Rotate
        response = await client.post(f"/api/v1/credentials/{str(old_credential.id)}/rotate")

        assert response.status_code == 200
        data = response.json()

        # Check response structure
        assert "old_credential" in data
        assert "new_credential" in data
        assert "raw_key" in data

        # Old credential should be revoked
        assert data["old_credential"]["revoked_at"] is not None
        assert data["old_credential"]["is_valid"] is False

        # New credential should be valid
        assert data["new_credential"]["is_valid"] is True
        assert data["new_credential"]["agent_id"] == str(root_agent.id)
        assert data["new_credential"]["scopes"] == ["read", "write"]

        # New key should be different
        new_key = data["raw_key"]
        assert new_key != old_key
        assert len(new_key) == 32

        # Old key should not verify
        old_verified = await service.verify_credential(old_key)
        assert old_verified is None

        # New key should verify
        new_verified = await service.verify_credential(new_key)
        assert new_verified is not None

    async def test_rotate_credential_not_found(self, client: AsyncClient) -> None:
        """Test rotating a non-existent credential."""
        from uuid_extensions import uuid7

        response = await client.post(f"/api/v1/credentials/{str(uuid7())}/rotate")

        assert response.status_code == 404

    async def test_credential_api_raw_key_never_stored(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test that raw API key is never stored in database."""
        # Create credential via API
        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "api_key",
            },
        )

        assert response.status_code == 201
        raw_key = response.json()["raw_key"]

        # Verify raw key is not in database
        service = CredentialService(db_session)
        credentials = await service.list_credentials(agent_id=root_agent.id)

        for cred in credentials:
            # Raw key should not be in hash
            assert raw_key not in cred.hash
            # Only prefix should match
            assert raw_key.startswith(cred.prefix)

    async def test_credential_api_pagination(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test credential list pagination."""
        service = CredentialService(db_session)

        # Create multiple credentials
        for _ in range(10):
            await service.create_credential(agent_id=root_agent.id)

        # Test limit
        response = await client.get("/api/v1/credentials?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 5
        assert data["meta"]["limit"] == 5

        # Test offset
        response = await client.get("/api/v1/credentials?limit=5&offset=5")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 5
        assert data["meta"]["offset"] == 5

    async def test_credential_audit_events_created(
        self, client: AsyncClient, db_session: AsyncSession, root_agent: Agent
    ) -> None:
        """Test that audit events are created for credential operations."""
        from agentauth.services.audit import AuditService

        audit_service = AuditService(db_session)

        # Create credential
        response = await client.post(
            "/api/v1/credentials",
            json={
                "agent_id": str(root_agent.id),
                "type": "api_key",
            },
        )
        assert response.status_code == 201
        credential_id = response.json()["credential"]["id"]

        # Check audit event for creation
        events = await audit_service.get_events(event_type="credential.created")
        assert len(events) > 0
        create_event = events[0]
        assert create_event.event_type == "credential.created"
        assert create_event.action == "created"
        assert str(create_event.target_id) == credential_id

        # Revoke credential
        response = await client.delete(f"/api/v1/credentials/{credential_id}")
        assert response.status_code == 200

        # Check audit event for revocation
        events = await audit_service.get_events(event_type="credential.revoked")
        assert len(events) > 0
        revoke_event = events[0]
        assert revoke_event.event_type == "credential.revoked"
        assert revoke_event.action == "revoked"
        assert str(revoke_event.target_id) == credential_id
