"""Unit tests for list_policies access control scoping (task 5.3)."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from agentauth.api.v1.policies import router as policies_router
from agentauth.core.database import get_session
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.policy import Policy, PolicyEffect

_NOW = datetime.now(UTC)


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _make_policy(
    *,
    created_by_agent_id,
    name: str = "test-policy",
    effect: PolicyEffect = PolicyEffect.ALLOW,
    priority: int = 10,
    enabled: bool = True,
) -> Policy:
    """Construct a Policy instance without a DB session."""
    p = Policy(
        id=uuid4(),
        created_by_agent_id=created_by_agent_id,
        name=name,
        description="",
        effect=effect,
        subjects={"wildcard": True},
        resources={"wildcard": True},
        actions=["read"],
        conditions={},
        priority=priority,
        enabled=enabled,
    )
    # BaseModel timestamp defaults only fire on DB flush; set them manually.
    p.created_at = _NOW
    p.updated_at = _NOW
    return p


def _make_agent(
    *,
    trust_level: TrustLevel = TrustLevel.DELEGATED,
    parent_agent_id=None,
) -> Agent:
    """Construct an Agent instance for testing."""
    agent = Agent(
        id=uuid4(),
        parent_agent_id=parent_agent_id,
        name="test-agent",
        agent_type=AgentType.ASSISTANT,
        trust_level=trust_level,
        status=AgentStatus.ACTIVE,
        max_child_depth=2,
    )
    return agent


def _make_root_agent() -> Agent:
    return _make_agent(trust_level=TrustLevel.ROOT, parent_agent_id=None)


# ---------------------------------------------------------------------------
# Minimal FastAPI test app
# ---------------------------------------------------------------------------


def _build_test_app(state_agent: Agent | None, mock_session: AsyncMock) -> FastAPI:
    """Create a minimal FastAPI app with the policies router.

    Injects `state_agent` into `request.state.agent` via middleware, and
    overrides the DB session dependency with the provided async mock.
    """
    app = FastAPI()

    @app.middleware("http")
    async def inject_agent(request: Request, call_next):
        request.state.agent = state_agent
        if state_agent is not None:
            request.state.agent_id = state_agent.id
        return await call_next(request)

    app.include_router(policies_router, prefix="/api/v1")

    async def override_get_session() -> AsyncGenerator:
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestListPoliciesScoping:
    """Verify that list_policies only returns policies in the caller's trust hierarchy."""

    @pytest.mark.asyncio
    async def test_root_agent_sees_all_policies(self) -> None:
        """Root agent should receive all policies regardless of creator."""
        root = _make_root_agent()
        own_policy = _make_policy(created_by_agent_id=root.id, name="root-own")
        other_policy = _make_policy(created_by_agent_id=uuid4(), name="other-root")

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [own_policy, other_policy]
        mock_session.execute = AsyncMock(return_value=mock_result)

        app = _build_test_app(root, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        data = response.json()
        # Root agent gets all policies — no ancestor filter applied.
        assert data["total"] == 2
        names = {p["name"] for p in data["data"]}
        assert "root-own" in names
        assert "other-root" in names

    @pytest.mark.asyncio
    async def test_non_root_agent_only_sees_ancestor_policies(self) -> None:
        """Non-root agent should only see policies created by itself or its ancestors."""
        root_id = uuid4()
        child_agent = _make_agent(trust_level=TrustLevel.DELEGATED, parent_agent_id=root_id)
        ancestor_policy = _make_policy(created_by_agent_id=root_id, name="ancestor-policy")

        mock_session = AsyncMock()

        # First execute: ancestor CTE → [child_agent.id, root_id]
        ancestor_rows = MagicMock()
        ancestor_rows.fetchall.return_value = [(child_agent.id,), (root_id,)]

        # Second execute: filtered policy SELECT → only ancestor_policy
        policy_result = MagicMock()
        policy_result.scalars.return_value.all.return_value = [ancestor_policy]

        mock_session.execute = AsyncMock(side_effect=[ancestor_rows, policy_result])

        app = _build_test_app(child_agent, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["data"][0]["name"] == "ancestor-policy"

    @pytest.mark.asyncio
    async def test_non_root_agent_cannot_see_unrelated_policies(self) -> None:
        """Non-root agent must not see policies from an unrelated trust hierarchy."""
        root_a_id = uuid4()
        agent_a = _make_agent(trust_level=TrustLevel.DELEGATED, parent_agent_id=root_a_id)

        mock_session = AsyncMock()

        # Ancestor CTE: only agent_a and root_a
        ancestor_rows = MagicMock()
        ancestor_rows.fetchall.return_value = [(agent_a.id,), (root_a_id,)]

        # DB query with created_by_agent_id IN (ancestor_ids) → excludes unrelated
        policy_result = MagicMock()
        policy_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[ancestor_rows, policy_result])

        app = _build_test_app(agent_a, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    @pytest.mark.asyncio
    async def test_non_root_agent_with_no_ancestor_ids_returns_empty(self) -> None:
        """If the ancestor CTE returns nothing, list_policies returns an empty list."""
        agent = _make_agent(trust_level=TrustLevel.DELEGATED)

        mock_session = AsyncMock()

        # CTE returns empty (unknown agent or DB anomaly)
        empty_rows = MagicMock()
        empty_rows.fetchall.return_value = []

        mock_session.execute = AsyncMock(return_value=empty_rows)

        app = _build_test_app(agent, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    @pytest.mark.asyncio
    async def test_unauthenticated_request_returns_401(self) -> None:
        """list_policies must return 401 when no authenticated agent is present."""
        mock_session = AsyncMock()

        # Inject None as the agent — simulates missing authentication
        app = _build_test_app(None, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_root_agent_skips_ancestor_cte_query(self) -> None:
        """Root agent list_policies must NOT issue the ancestor CTE query."""
        root = _make_root_agent()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        app = _build_test_app(root, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        # Root agent path issues exactly ONE DB query (policy SELECT), not TWO.
        assert mock_session.execute.call_count == 1

    @pytest.mark.asyncio
    async def test_non_root_agent_issues_ancestor_cte_then_policy_query(self) -> None:
        """Non-root agent list_policies must issue two DB queries: CTE then policy SELECT."""
        root_id = uuid4()
        agent = _make_agent(trust_level=TrustLevel.DELEGATED, parent_agent_id=root_id)

        mock_session = AsyncMock()

        ancestor_rows = MagicMock()
        ancestor_rows.fetchall.return_value = [(agent.id,), (root_id,)]

        policy_result = MagicMock()
        policy_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[ancestor_rows, policy_result])

        app = _build_test_app(agent, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        # Exactly two DB calls: 1 ancestor CTE + 1 policy SELECT
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_enabled_only_filter_passes_through(self) -> None:
        """The enabled_only query param must be forwarded to the DB query."""
        root = _make_root_agent()
        enabled_policy = _make_policy(
            created_by_agent_id=root.id, name="enabled", enabled=True
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [enabled_policy]
        mock_session.execute = AsyncMock(return_value=mock_result)

        app = _build_test_app(root, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies?enabled_only=true")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["data"][0]["name"] == "enabled"

    @pytest.mark.asyncio
    async def test_deeply_nested_agent_sees_full_ancestor_chain_policies(self) -> None:
        """Agent 3 levels deep should see policies created by any ancestor."""
        root_id = uuid4()
        mid_id = uuid4()
        leaf_agent = _make_agent(trust_level=TrustLevel.DELEGATED, parent_agent_id=mid_id)

        root_policy = _make_policy(created_by_agent_id=root_id, name="root-policy")
        mid_policy = _make_policy(created_by_agent_id=mid_id, name="mid-policy")

        mock_session = AsyncMock()

        ancestor_rows = MagicMock()
        ancestor_rows.fetchall.return_value = [
            (leaf_agent.id,),
            (mid_id,),
            (root_id,),
        ]

        policy_result = MagicMock()
        policy_result.scalars.return_value.all.return_value = [root_policy, mid_policy]

        mock_session.execute = AsyncMock(side_effect=[ancestor_rows, policy_result])

        app = _build_test_app(leaf_agent, mock_session)

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/policies")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        names = {p["name"] for p in data["data"]}
        assert "root-policy" in names
        assert "mid-policy" in names
