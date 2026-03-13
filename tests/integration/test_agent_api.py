"""Tests for Agent API endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel


class TestAgentBootstrap:
    """Tests for root agent bootstrap endpoint."""

    @pytest.mark.asyncio
    async def test_bootstrap_root_agent_success(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """Test successful root agent creation."""
        data = {
            "name": "root-orchestrator",
            "agent_type": "orchestrator",
            "description": "Root orchestrator agent",
            "max_child_depth": 3,
            "metadata": {"version": "1.0.0"},
        }

        response = await client.post("/api/v1/agents/bootstrap", json=data)
        assert response.status_code == 201

        json_data = response.json()
        assert json_data["data"]["name"] == "root-orchestrator"
        assert json_data["data"]["agent_type"] == "orchestrator"
        assert json_data["data"]["trust_level"] == "root"
        assert json_data["data"]["parent_agent_id"] is None
        assert json_data["data"]["status"] == "active"
        assert json_data["meta"]["is_root"] is True

    @pytest.mark.asyncio
    async def test_bootstrap_root_agent_minimal(
        self,
        client: AsyncClient,
    ) -> None:
        """Test root agent creation with minimal fields."""
        data = {
            "name": "minimal-root",
            "agent_type": "autonomous",
        }

        response = await client.post("/api/v1/agents/bootstrap", json=data)
        assert response.status_code == 201

        json_data = response.json()
        assert json_data["data"]["name"] == "minimal-root"
        assert json_data["data"]["trust_level"] == "root"
        assert json_data["data"]["parent_agent_id"] is None


class TestAgentCreation:
    """Tests for child agent creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_child_agent_success(
        self,
        client: AsyncClient,
        root_agent: Agent,
    ) -> None:
        """Test successful child agent creation."""
        data = {
            "parent_agent_id": str(root_agent.id),
            "name": "child-agent-1",
            "agent_type": "assistant",
            "description": "Child assistant agent",
            "max_child_depth": 2,
        }

        response = await client.post("/api/v1/agents", json=data)
        assert response.status_code == 201

        json_data = response.json()
        assert json_data["data"]["name"] == "child-agent-1"
        assert json_data["data"]["agent_type"] == "assistant"
        assert json_data["data"]["trust_level"] == "delegated"
        assert json_data["data"]["parent_agent_id"] == str(root_agent.id)
        assert json_data["meta"]["is_root"] is False

    @pytest.mark.asyncio
    async def test_create_child_agent_duplicate_name(
        self,
        client: AsyncClient,
        root_agent: Agent,
    ) -> None:
        """Test creating child agent with duplicate name under same parent returns 409."""
        data = {
            "parent_agent_id": str(root_agent.id),
            "name": "duplicate-name",
            "agent_type": "tool",
        }

        # Create first agent
        response = await client.post("/api/v1/agents", json=data)
        assert response.status_code == 201

        # Try to create another with same name — expect 409 Conflict
        response = await client.post("/api/v1/agents", json=data)
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail["status"] == 409
        assert "already exists" in detail["detail"]

    @pytest.mark.asyncio
    async def test_create_child_agent_nonexistent_parent(
        self,
        client: AsyncClient,
    ) -> None:
        """Test creating child agent with nonexistent parent."""
        data = {
            "parent_agent_id": "00000000-0000-0000-0000-000000000000",
            "name": "orphan-agent",
            "agent_type": "tool",
        }

        response = await client.post("/api/v1/agents", json=data)
        assert response.status_code == 400
        assert "not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_child_agent_max_depth_validation(
        self,
        client: AsyncClient,
        root_agent: Agent,
    ) -> None:
        """Test that child max_depth is attenuated from parent."""
        data = {
            "parent_agent_id": str(root_agent.id),
            "name": "depth-test-child",
            "agent_type": "tool",
            "max_child_depth": 10,  # Request more than parent allows
        }

        response = await client.post("/api/v1/agents", json=data)
        assert response.status_code == 201

        json_data = response.json()
        # Should be min(requested, parent.max_child_depth - 1)
        # Root has max_child_depth=3, so child should get 2
        assert json_data["data"]["max_child_depth"] <= root_agent.max_child_depth - 1


class TestAgentList:
    """Tests for agent listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_all_agents(
        self,
        client: AsyncClient,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Test listing all agents."""
        response = await client.get("/api/v1/agents")
        assert response.status_code == 200

        json_data = response.json()
        assert len(json_data["data"]) >= 2
        assert json_data["meta"]["limit"] == 50

    @pytest.mark.asyncio
    async def test_list_agents_by_parent(
        self,
        client: AsyncClient,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Test listing agents filtered by parent."""
        response = await client.get(f"/api/v1/agents?parent_agent_id={root_agent.id}")
        assert response.status_code == 200

        json_data = response.json()
        assert all(agent["parent_agent_id"] == str(root_agent.id) for agent in json_data["data"])

    @pytest.mark.asyncio
    async def test_list_agents_by_status(
        self,
        client: AsyncClient,
    ) -> None:
        """Test listing agents filtered by status."""
        response = await client.get("/api/v1/agents?status=active")
        assert response.status_code == 200

        json_data = response.json()
        assert all(agent["status"] == "active" for agent in json_data["data"])

    @pytest.mark.asyncio
    async def test_list_agents_pagination(
        self,
        client: AsyncClient,
    ) -> None:
        """Test agent list pagination."""
        response = await client.get("/api/v1/agents?limit=1&offset=0")
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["meta"]["limit"] == 1
        assert json_data["meta"]["offset"] == 0


class TestAgentDetail:
    """Tests for agent detail endpoint."""

    @pytest.mark.asyncio
    async def test_get_agent_success(
        self,
        client: AsyncClient,
        root_agent: Agent,
    ) -> None:
        """Test getting agent details."""
        response = await client.get(f"/api/v1/agents/{root_agent.id}")
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["data"]["id"] == str(root_agent.id)
        assert json_data["data"]["name"] == root_agent.name
        assert json_data["meta"]["is_root"] is True
        assert json_data["meta"]["is_active"] is True

    @pytest.mark.asyncio
    async def test_get_agent_not_found(
        self,
        client: AsyncClient,
    ) -> None:
        """Test getting nonexistent agent."""
        response = await client.get("/api/v1/agents/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404


class TestAgentUpdate:
    """Tests for agent update endpoint."""

    @pytest.mark.asyncio
    async def test_update_agent_success(
        self,
        client: AsyncClient,
        child_agent: Agent,
    ) -> None:
        """Test updating agent details."""
        data = {
            "name": "updated-agent-name",
            "description": "Updated description",
        }

        response = await client.patch(f"/api/v1/agents/{child_agent.id}", json=data)
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["data"]["name"] == "updated-agent-name"
        assert json_data["data"]["description"] == "Updated description"

    @pytest.mark.asyncio
    async def test_update_agent_partial(
        self,
        client: AsyncClient,
        child_agent: Agent,
    ) -> None:
        """Test partial update of agent."""
        original_name = child_agent.name
        data = {"description": "Only update description"}

        response = await client.patch(f"/api/v1/agents/{child_agent.id}", json=data)
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["data"]["name"] == original_name  # Unchanged
        assert json_data["data"]["description"] == "Only update description"

    @pytest.mark.asyncio
    async def test_update_agent_not_found(
        self,
        client: AsyncClient,
    ) -> None:
        """Test updating nonexistent agent."""
        data = {"name": "new-name"}
        response = await client.patch(
            "/api/v1/agents/00000000-0000-0000-0000-000000000000",
            json=data,
        )
        assert response.status_code == 404


class TestAgentDeactivation:
    """Tests for agent deactivation endpoint."""

    @pytest.mark.asyncio
    async def test_deactivate_agent_success(
        self,
        client: AsyncClient,
        child_agent: Agent,
    ) -> None:
        """Test deactivating an agent."""
        response = await client.delete(f"/api/v1/agents/{child_agent.id}")
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["data"]["status"] == "suspended"
        assert json_data["data"]["deactivated_at"] is not None
        assert json_data["meta"]["deactivated_at"] is not None

    @pytest.mark.asyncio
    async def test_deactivate_agent_not_found(
        self,
        client: AsyncClient,
    ) -> None:
        """Test deactivating nonexistent agent."""
        response = await client.delete("/api/v1/agents/00000000-0000-0000-0000-000000000000")
        assert response.status_code == 404


class TestAgentChildren:
    """Tests for agent children endpoint."""

    @pytest.mark.asyncio
    async def test_list_agent_children_success(
        self,
        client: AsyncClient,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Test listing children of an agent."""
        response = await client.get(f"/api/v1/agents/{root_agent.id}/children")
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["meta"]["parent_agent_id"] == str(root_agent.id)
        assert len(json_data["data"]) >= 1
        assert any(agent["id"] == str(child_agent.id) for agent in json_data["data"])

    @pytest.mark.asyncio
    async def test_list_agent_children_parent_not_found(
        self,
        client: AsyncClient,
    ) -> None:
        """Test listing children of nonexistent agent."""
        response = await client.get("/api/v1/agents/00000000-0000-0000-0000-000000000000/children")
        assert response.status_code == 404


class TestAgentCredentials:
    """Tests for agent credentials endpoint."""

    @pytest.mark.asyncio
    async def test_list_agent_credentials_empty(
        self,
        client: AsyncClient,
        root_agent: Agent,
    ) -> None:
        """Test listing credentials for agent with no credentials."""
        response = await client.get(f"/api/v1/agents/{root_agent.id}/credentials")
        assert response.status_code == 200

        json_data = response.json()
        assert json_data["meta"]["credentials_count"] == 0
        assert json_data["meta"]["credentials"] == []

    @pytest.mark.asyncio
    async def test_list_agent_credentials_not_found(
        self,
        client: AsyncClient,
    ) -> None:
        """Test listing credentials for nonexistent agent."""
        response = await client.get(
            "/api/v1/agents/00000000-0000-0000-0000-000000000000/credentials"
        )
        assert response.status_code == 404


class TestRootAgentValidation:
    """Tests for root agent specific behavior."""

    @pytest.mark.asyncio
    async def test_root_agents_have_null_parent(
        self,
        client: AsyncClient,
    ) -> None:
        """Test that root agents have parent_agent_id=null."""
        data = {
            "name": "test-root",
            "agent_type": "orchestrator",
        }

        response = await client.post("/api/v1/agents/bootstrap", json=data)
        assert response.status_code == 201

        json_data = response.json()
        assert json_data["data"]["parent_agent_id"] is None

    @pytest.mark.asyncio
    async def test_root_agents_have_root_trust_level(
        self,
        client: AsyncClient,
    ) -> None:
        """Test that root agents have trust_level=root."""
        data = {
            "name": "test-root-trust",
            "agent_type": "orchestrator",
        }

        response = await client.post("/api/v1/agents/bootstrap", json=data)
        assert response.status_code == 201

        json_data = response.json()
        assert json_data["data"]["trust_level"] == "root"
