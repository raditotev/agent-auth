"""Integration tests for authentication middleware with full application."""

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.main import create_app
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService
from agentauth.services.identity import IdentityService


@pytest.fixture
def app():
    """Create the full application for integration testing."""
    return create_app()


@pytest.mark.asyncio
class TestAuthenticationIntegration:
    """Integration tests for authentication flow."""

    async def test_full_auth_flow_bootstrap_to_authenticated_request(
        self, app, db_session: AsyncSession
    ):
        """Test complete flow: bootstrap agent, create credential, make authenticated request."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Step 1: Bootstrap a root agent (no auth required)
            bootstrap_data = {
                "name": "Integration Test Agent",
                "agent_type": "orchestrator",
                "description": "Agent for integration testing",
                "max_child_depth": 3,
                "metadata": {"test": "integration"},
            }

            response = await client.post(
                "/api/v1/agents/bootstrap", json=bootstrap_data
            )
            assert response.status_code == 201
            agent_data = response.json()["data"]
            agent_id = agent_data["id"]

            # Step 2: Create a credential for this agent
            # (In real scenario, bootstrap might return initial credential)
            # For now, we'll create it directly via service
            identity_service = IdentityService(db_session)
            agent = await identity_service.get_agent(agent_id)

            credential_service = CredentialService(db_session)
            credential, raw_key = await credential_service.create_credential(
                agent_id=agent.id,
                credential_type=CredentialType.API_KEY,
                scopes=["agents.read", "agents.write"],
            )
            await db_session.commit()

            # Step 3: List agents using authenticated request
            response = await client.get(
                "/api/v1/agents", headers={"X-Agent-Key": raw_key}
            )
            assert response.status_code == 200
            agents_list = response.json()
            assert "data" in agents_list
            assert len(agents_list["data"]) > 0

    async def test_create_child_agent_requires_auth(self, app, db_session: AsyncSession):
        """Creating a child agent should require authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Try to create agent without auth
            agent_data = {
                "name": "Child Agent",
                "agent_type": "assistant",
                "parent_agent_id": "00000000-0000-0000-0000-000000000000",
            }

            response = await client.post("/api/v1/agents", json=agent_data)
            assert response.status_code == 401
            assert response.headers["content-type"] == "application/problem+json"

    async def test_credential_operations_require_auth(
        self, app, db_session: AsyncSession
    ):
        """Credential operations should require authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Try to list credentials without auth
            response = await client.get("/api/v1/credentials")
            assert response.status_code == 401

            # Try to create credential without auth
            response = await client.post(
                "/api/v1/credentials",
                json={
                    "agent_id": "00000000-0000-0000-0000-000000000000",
                    "type": "api_key",
                },
            )
            assert response.status_code == 401

    async def test_authenticated_agent_can_create_child(
        self, app, db_session: AsyncSession
    ):
        """Authenticated root agent should be able to create child agents."""
        # Create root agent and credential
        identity_service = IdentityService(db_session)

        from agentauth.schemas.agent import AgentBootstrapCreate

        root_data = AgentBootstrapCreate(
            name="Parent Agent",
            agent_type=AgentType.ORCHESTRATOR,
            description="Parent for child creation test",
        )
        root_agent = await identity_service.create_root_agent(root_data)

        credential_service = CredentialService(db_session)
        credential, raw_key = await credential_service.create_credential(
            agent_id=root_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["agents.write"],
        )
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Create child agent
            child_data = {
                "name": "Child Agent",
                "agent_type": "assistant",
                "parent_agent_id": str(root_agent.id),
                "description": "Child of authenticated agent",
            }

            response = await client.post(
                "/api/v1/agents",
                json=child_data,
                headers={"X-Agent-Key": raw_key},
            )
            assert response.status_code == 201
            child_agent_data = response.json()["data"]
            assert child_agent_data["name"] == "Child Agent"
            assert child_agent_data["parent_agent_id"] == str(root_agent.id)
            assert child_agent_data["trust_level"] == TrustLevel.DELEGATED.value

    async def test_agent_can_list_own_credentials(self, app, db_session: AsyncSession):
        """Agent should be able to list its own credentials."""
        # Create agent with credential
        identity_service = IdentityService(db_session)

        from agentauth.schemas.agent import AgentBootstrapCreate

        agent_data = AgentBootstrapCreate(
            name="Credential Owner",
            agent_type=AgentType.ORCHESTRATOR,
        )
        agent = await identity_service.create_root_agent(agent_data)

        credential_service = CredentialService(db_session)
        credential1, raw_key1 = await credential_service.create_credential(
            agent_id=agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["credentials.read"],
        )
        credential2, raw_key2 = await credential_service.create_credential(
            agent_id=agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["credentials.read"],
        )
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # List credentials using first key
            response = await client.get(
                f"/api/v1/credentials?agent_id={agent.id}",
                headers={"X-Agent-Key": raw_key1},
            )
            assert response.status_code == 200
            creds_data = response.json()
            assert "data" in creds_data
            # Should see at least 2 credentials
            assert len(creds_data["data"]) >= 2

    async def test_revoked_credential_cannot_authenticate(
        self, app, db_session: AsyncSession
    ):
        """Revoked credential should not be able to authenticate."""
        # Create agent with credential
        identity_service = IdentityService(db_session)

        from agentauth.schemas.agent import AgentBootstrapCreate

        agent_data = AgentBootstrapCreate(
            name="Revoke Test Agent",
            agent_type=AgentType.ORCHESTRATOR,
        )
        agent = await identity_service.create_root_agent(agent_data)

        credential_service = CredentialService(db_session)
        credential, raw_key = await credential_service.create_credential(
            agent_id=agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["agents.read"],
        )
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # First request should succeed
            response = await client.get(
                "/api/v1/agents", headers={"X-Agent-Key": raw_key}
            )
            assert response.status_code == 200

            # Revoke the credential
            await credential_service.revoke_credential(credential.id)
            await db_session.commit()

            # Second request should fail
            response = await client.get(
                "/api/v1/agents", headers={"X-Agent-Key": raw_key}
            )
            assert response.status_code == 401
            problem = response.json()
            assert problem["title"] == "Invalid Authentication"

    async def test_suspended_agent_cannot_authenticate(
        self, app, db_session: AsyncSession
    ):
        """Suspended agent should not be able to authenticate."""
        # Create agent with credential
        identity_service = IdentityService(db_session)

        from agentauth.schemas.agent import AgentBootstrapCreate

        agent_data = AgentBootstrapCreate(
            name="Suspend Test Agent",
            agent_type=AgentType.ORCHESTRATOR,
        )
        agent = await identity_service.create_root_agent(agent_data)

        credential_service = CredentialService(db_session)
        credential, raw_key = await credential_service.create_credential(
            agent_id=agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["agents.read"],
        )
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # First request should succeed
            response = await client.get(
                "/api/v1/agents", headers={"X-Agent-Key": raw_key}
            )
            assert response.status_code == 200

            # Suspend the agent
            agent.deactivate()
            await db_session.commit()

            # Second request should fail
            response = await client.get(
                "/api/v1/agents", headers={"X-Agent-Key": raw_key}
            )
            assert response.status_code == 401
            problem = response.json()
            assert problem["title"] == "Agent Inactive"
            assert "suspended" in problem["detail"].lower()

    async def test_public_endpoints_accessible_without_auth(self, app):
        """Public endpoints should be accessible without authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Health check
            response = await client.get("/health")
            assert response.status_code == 200

            # Readiness check
            response = await client.get("/ready")
            assert response.status_code == 200

            # Bootstrap endpoint
            bootstrap_data = {
                "name": "Public Access Test",
                "agent_type": "orchestrator",
            }
            response = await client.post("/api/v1/agents/bootstrap", json=bootstrap_data)
            assert response.status_code == 201  # Should not be 401
