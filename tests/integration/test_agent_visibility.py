"""Integration tests for relationship-based agent visibility scoping.

Task 7.4 — verifies that:
1. Root agents without admin.agents.list see only their own subtree + delegation peers.
2. Root agents with admin.agents.list see all agents.
3. get_agent returns 404 (not 403) for agents outside the caller's visibility.
4. Delegation peers (both directions) are visible.
5. The total count in list_agents meta reflects the filtered result.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService


async def _make_restricted_client(
    db_engine,
    db_session: AsyncSession,
    agent: Agent,
    *,
    extra_scopes: list[str] | None = None,
):
    """
    Create an AsyncClient authenticated as *agent* WITHOUT admin.agents.list scope.
    The caller is responsible for cleaning up the client (use as async context manager).
    """
    import agentauth.core.database as db_module
    from collections.abc import AsyncGenerator

    from httpx import ASGITransport, AsyncClient as _Client
    from sqlalchemy.ext.asyncio import AsyncSession as _Session
    from sqlalchemy.ext.asyncio import async_sessionmaker as _sm

    from agentauth.core.database import get_session
    from agentauth.main import create_app

    scopes = extra_scopes or ["agents.read", "agents.write"]
    cred_service = CredentialService(db_session)
    _, api_key = await cred_service.create_credential(
        agent_id=agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=scopes,
    )
    await db_session.commit()

    test_session_maker = _sm(db_engine, class_=_Session, expire_on_commit=False)
    original = db_module.async_session_maker
    db_module.async_session_maker = test_session_maker

    app = create_app()

    async def override_session() -> AsyncGenerator[_Session, None]:
        yield db_session

    app.dependency_overrides[get_session] = override_session

    client = _Client(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-Agent-Key": api_key},
    )

    # Wrap cleanup: restore on exit
    original_overrides = dict(app.dependency_overrides)

    class _CtxClient:
        def __init__(self, c, app, sm_orig, overrides_orig):
            self._c = c
            self._app = app
            self._sm_orig = sm_orig

        async def __aenter__(self):
            await self._c.__aenter__()
            return self._c

        async def __aexit__(self, *args):
            self._app.dependency_overrides.clear()
            db_module.async_session_maker = self._sm_orig
            await self._c.__aexit__(*args)

    return _CtxClient(client, app, original, original_overrides)


@pytest.mark.asyncio
class TestAgentVisibility:
    """Relationship-based visibility for list_agents and get_agent."""

    async def _create_unrelated_root(
        self, db_session: AsyncSession, name: str
    ) -> Agent:
        agent = Agent(
            parent_agent_id=None,
            name=name,
            agent_type=AgentType.AUTONOMOUS,
            trust_level=TrustLevel.ROOT,
            status=AgentStatus.ACTIVE,
            max_child_depth=3,
            agent_metadata={},
        )
        db_session.add(agent)
        await db_session.flush()
        await db_session.refresh(agent)
        return agent

    # ------------------------------------------------------------------ admin scope

    async def test_admin_scope_sees_all_agents(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """A caller with admin.agents.list can list all agents including unrelated ones."""
        # client fixture uses admin.agents.list — must see root_agent
        response = await client.get("/api/v1/agents")
        assert response.status_code == 200
        ids = {a["id"] for a in response.json()["data"]}
        assert str(root_agent.id) in ids

    async def test_admin_scope_get_agent_any_id(
        self, client: AsyncClient, root_agent: Agent
    ) -> None:
        """A caller with admin.agents.list can fetch any agent by ID."""
        response = await client.get(f"/api/v1/agents/{root_agent.id}")
        assert response.status_code == 200

    # ------------------------------------------------------------------ no admin scope

    async def test_restricted_caller_sees_only_own_subtree(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
        auth_child_agent: Agent,
        root_agent: Agent,
    ) -> None:
        """Without admin.agents.list, caller sees only itself and its descendants."""
        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get("/api/v1/agents")
            assert response.status_code == 200
            ids = {a["id"] for a in response.json()["data"]}

            # Must see itself and its child
            assert str(auth_agent.id) in ids
            assert str(auth_child_agent.id) in ids

            # Must NOT see an unrelated root agent
            assert str(root_agent.id) not in ids

    async def test_restricted_caller_get_agent_invisible_returns_404(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
        root_agent: Agent,
    ) -> None:
        """get_agent returns 404 (not 403) for agents outside visibility."""
        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get(f"/api/v1/agents/{root_agent.id}")
            assert response.status_code == 404

    async def test_restricted_caller_get_agent_self_visible(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
    ) -> None:
        """A caller can always fetch itself."""
        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get(f"/api/v1/agents/{auth_agent.id}")
            assert response.status_code == 200
            assert response.json()["data"]["id"] == str(auth_agent.id)

    async def test_list_meta_total_reflects_filtered_count(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
        auth_child_agent: Agent,
        root_agent: Agent,
    ) -> None:
        """The 'total' in response meta reflects the filtered (visible) agent count."""
        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get("/api/v1/agents")
            data = response.json()
            returned_count = len(data["data"])
            meta_total = data["meta"]["total"]
            # Meta total must match the number of agents actually returned
            assert meta_total == returned_count

    # ------------------------------------------------------------------ delegation peers

    async def test_delegation_peer_is_visible(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
    ) -> None:
        """An agent that auth_agent has delegated TO is visible."""
        from agentauth.services.delegation import DelegationService

        # Create a second root agent (not in auth_agent's subtree)
        other_agent = await self._create_unrelated_root(
            db_session, "vis-delegation-peer"
        )
        # Give other_agent a credential with scopes
        cred_svc = CredentialService(db_session)
        await cred_svc.create_credential(
            agent_id=other_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        # Create delegation: auth_agent → other_agent
        deleg_svc = DelegationService(db_session)
        await deleg_svc.create_delegation(
            delegator_agent_id=auth_agent.id,
            delegate_agent_id=other_agent.id,
            scopes=["api.read"],
        )

        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get("/api/v1/agents")
            ids = {a["id"] for a in response.json()["data"]}
            # other_agent is a delegation peer — must be visible
            assert str(other_agent.id) in ids

    async def test_reverse_delegation_peer_is_visible(
        self,
        db_engine,
        db_session: AsyncSession,
        auth_agent: Agent,
    ) -> None:
        """An agent that delegated TO auth_agent (reverse direction) is also visible."""
        from agentauth.services.delegation import DelegationService

        other_agent = await self._create_unrelated_root(
            db_session, "vis-reverse-delegation-peer"
        )
        cred_svc = CredentialService(db_session)
        await cred_svc.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        # Delegation from other_agent → auth_agent
        deleg_svc = DelegationService(db_session)
        await deleg_svc.create_delegation(
            delegator_agent_id=other_agent.id,
            delegate_agent_id=auth_agent.id,
            scopes=["api.read"],
        )

        async with await _make_restricted_client(
            db_engine, db_session, auth_agent
        ) as restricted:
            response = await restricted.get("/api/v1/agents")
            ids = {a["id"] for a in response.json()["data"]}
            # other_agent delegated TO auth_agent — must be visible
            assert str(other_agent.id) in ids
