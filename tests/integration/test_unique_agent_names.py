"""Integration tests for unique agent name enforcement.

Task 7.3 — verifies that:
1. Duplicate root agent names are rejected with 409 Conflict.
2. Duplicate child agent names under the same parent are rejected with 409.
3. The same name is allowed under different parents (sibling uniqueness not required).
4. All 409 responses use RFC 7807 problem detail format.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent


@pytest.mark.asyncio
class TestUniqueRootAgentNames:
    """Root agent names must be globally unique."""

    async def test_bootstrap_duplicate_root_agent_name_returns_409(
        self, client: AsyncClient
    ) -> None:
        """Creating a second root agent with the same name returns 409 Conflict."""
        name = "unique-root-conflict-test"
        payload = {"name": name, "agent_type": "orchestrator"}

        # First registration must succeed
        first = await client.post("/api/v1/agents/bootstrap", json=payload)
        assert first.status_code == 201

        # Second registration with the same name must be rejected
        second = await client.post("/api/v1/agents/bootstrap", json=payload)
        assert second.status_code == 409

        detail = second.json()["detail"]
        assert detail["status"] == 409
        assert detail["type"] == "https://agentauth.dev/problems/agent-name-conflict"
        assert name in detail["detail"]

    async def test_quickstart_duplicate_root_name_returns_409(
        self, client: AsyncClient, signing_key_rsa: object
    ) -> None:
        """Quickstart returns 409 when the requested root agent name already exists."""
        name = "unique-quickstart-conflict-test"
        payload = {"name": name, "agent_type": "autonomous"}

        first = await client.post("/api/v1/agents/quickstart", json=payload)
        assert first.status_code == 201

        second = await client.post("/api/v1/agents/quickstart", json=payload)
        assert second.status_code == 409

        detail = second.json()["detail"]
        assert detail["status"] == 409

    async def test_different_root_names_are_allowed(self, client: AsyncClient) -> None:
        """Two root agents with different names can coexist."""
        first = await client.post(
            "/api/v1/agents/bootstrap",
            json={"name": "unique-root-alpha", "agent_type": "orchestrator"},
        )
        second = await client.post(
            "/api/v1/agents/bootstrap",
            json={"name": "unique-root-beta", "agent_type": "orchestrator"},
        )
        assert first.status_code == 201
        assert second.status_code == 201


@pytest.mark.asyncio
class TestUniqueChildAgentNames:
    """Child agent names must be unique per parent."""

    async def test_duplicate_child_name_under_same_parent_returns_409(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """Creating two children with the same name under the same parent returns 409."""
        payload = {
            "parent_agent_id": str(root_agent.id),
            "name": "child-dupe-name",
            "agent_type": "tool",
        }

        first = await client.post("/api/v1/agents", json=payload)
        assert first.status_code == 201

        second = await client.post("/api/v1/agents", json=payload)
        assert second.status_code == 409

        detail = second.json()["detail"]
        assert detail["status"] == 409
        assert detail["type"] == "https://agentauth.dev/problems/agent-name-conflict"
        assert "child-dupe-name" in detail["detail"]

    async def test_same_child_name_under_different_parents_is_allowed(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """The same child name is allowed under different parents."""
        from agentauth.models.agent import AgentStatus, AgentType, TrustLevel

        # Create two separate root agents
        parent1 = Agent(
            parent_agent_id=None,
            name="sib-parent-1",
            agent_type=AgentType.ORCHESTRATOR,
            trust_level=TrustLevel.ROOT,
            status=AgentStatus.ACTIVE,
            max_child_depth=3,
            agent_metadata={},
        )
        parent2 = Agent(
            parent_agent_id=None,
            name="sib-parent-2",
            agent_type=AgentType.ORCHESTRATOR,
            trust_level=TrustLevel.ROOT,
            status=AgentStatus.ACTIVE,
            max_child_depth=3,
            agent_metadata={},
        )
        db_session.add(parent1)
        db_session.add(parent2)
        await db_session.flush()
        await db_session.refresh(parent1)
        await db_session.refresh(parent2)

        child_name = "shared-child-name"

        # First child under parent1 — must succeed
        resp1 = await client.post(
            "/api/v1/agents",
            json={
                "parent_agent_id": str(parent1.id),
                "name": child_name,
                "agent_type": "tool",
            },
        )
        assert resp1.status_code == 201

        # Second child with the same name under parent2 — must also succeed
        resp2 = await client.post(
            "/api/v1/agents",
            json={
                "parent_agent_id": str(parent2.id),
                "name": child_name,
                "agent_type": "tool",
            },
        )
        assert resp2.status_code == 201, resp2.text

    async def test_409_response_body_is_rfc7807(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """The 409 conflict response body follows RFC 7807 problem detail format."""
        payload = {
            "parent_agent_id": str(root_agent.id),
            "name": "rfc7807-test-child",
            "agent_type": "tool",
        }
        await client.post("/api/v1/agents", json=payload)
        response = await client.post("/api/v1/agents", json=payload)

        assert response.status_code == 409
        body = response.json()
        detail = body["detail"]
        assert "type" in detail
        assert "title" in detail
        assert "status" in detail
        assert "detail" in detail
        assert detail["status"] == 409
