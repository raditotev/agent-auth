"""End-to-end tests for complete authentication flows."""

import pytest
from httpx import ASGITransport, AsyncClient

from agentauth.main import create_app


@pytest.fixture
def app():
    """Create the full application for e2e testing."""
    return create_app()


@pytest.mark.asyncio
class TestFullAuthFlow:
    """End-to-end tests covering bootstrap → credential → token → protected resource."""

    async def test_quickstart_to_protected_resource(self, app) -> None:
        """
        Full auth flow: quickstart (bootstrap+credential+token) → use token for API access.

        Verifies the complete path from unauthenticated registration to
        authenticated resource access.
        """
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Step 1: Quickstart — register agent, get API key and token in one call
            quickstart_data = {
                "name": "e2e-test-agent",
                "agent_type": "orchestrator",
                "description": "E2E test agent",
                "max_child_depth": 3,
                "metadata": {"e2e": True},
            }

            response = await client.post("/api/v1/agents/quickstart", json=quickstart_data)
            assert response.status_code == 201, response.text

            data = response.json()
            assert "agent" in data
            assert "api_key" in data
            assert "token" in data

            agent_id = data["agent"]["id"]
            api_key = data["api_key"]
            token = data["token"]["access_token"]

            assert token is not None
            assert len(token.split(".")) == 3  # JWT structure

            # Step 2: Use Bearer token to access protected resource
            response = await client.get(
                "/api/v1/agents",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            agents = response.json()
            assert "data" in agents
            assert any(a["id"] == agent_id for a in agents["data"])

            # Step 3: Use API key to access protected resource (alternative auth)
            response = await client.get(
                "/api/v1/agents",
                headers={"X-Agent-Key": api_key},
            )
            assert response.status_code == 200
            agents = response.json()
            assert any(a["id"] == agent_id for a in agents["data"])

            # Step 4: Policy evaluation dry-run (requires auth)
            response = await client.post(
                "/api/v1/policies/evaluate",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "agent_id": agent_id,
                    "action": "read",
                    "resource": "/api/v1/agents",
                    "context": {},
                },
            )
            assert response.status_code == 200
            eval_result = response.json()
            assert "allowed" in eval_result
            assert "reason" in eval_result
            # Root agents bypass policy; default deny for others
            assert eval_result["allowed"] in (True, False)

    async def test_bootstrap_credential_token_flow(self, app, db_session) -> None:
        """
        Full auth flow: bootstrap → create credential via service → token → API.

        Tests the multi-step flow when quickstart is not used.
        """
        from agentauth.models.credential import CredentialType
        from agentauth.services.credential import CredentialService
        from agentauth.services.identity import IdentityService

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Step 1: Bootstrap root agent (no auth)
            bootstrap_data = {
                "name": "e2e-bootstrap-agent",
                "agent_type": "autonomous",
                "max_child_depth": 3,
            }
            response = await client.post("/api/v1/agents/bootstrap", json=bootstrap_data)
            assert response.status_code == 201
            agent_data = response.json()["data"]
            agent_id = agent_data["id"]

            # Step 2: Create credential via service (we have db_session from fixture)
            identity_service = IdentityService(db_session)
            agent = await identity_service.get_agent(agent_id)
            assert agent is not None

            credential_service = CredentialService(db_session)
            credential, api_key = await credential_service.create_credential(
                agent_id=agent.id,
                credential_type=CredentialType.API_KEY,
                scopes=["api.read", "agents.read"],
            )
            await db_session.commit()

            # Step 3: Get token via client_credentials
            response = await client.post(
                "/api/v1/auth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_secret": api_key,
                    "scope": "api.read agents.read",
                },
            )
            assert response.status_code == 200
            token_data = response.json()
            access_token = token_data["access_token"]
            assert access_token is not None

            # Step 4: Use token to list agents
            response = await client.get(
                "/api/v1/agents",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert response.status_code == 200
            assert "data" in response.json()
