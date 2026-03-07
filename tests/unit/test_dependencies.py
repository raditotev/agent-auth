"""Unit tests for FastAPI dependency injection utilities."""

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentauth.api.middleware import AuthenticationMiddleware
from agentauth.dependencies import (
    CurrentAgent,
    RootAgent,
    get_current_agent,
    require_root_agent,
    require_trust_level,
)
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService


@pytest_asyncio.fixture
async def test_session_maker(db_engine) -> async_sessionmaker[AsyncSession]:
    """Create test session maker."""
    return async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


@pytest_asyncio.fixture
async def root_agent(db_session: AsyncSession) -> Agent:
    """Create a root agent."""
    agent = Agent(
        name="Root Agent",
        agent_type=AgentType.ORCHESTRATOR,
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def delegated_agent(db_session: AsyncSession, root_agent: Agent) -> Agent:
    """Create a delegated (child) agent."""
    agent = Agent(
        name="Delegated Agent",
        parent_agent_id=root_agent.id,
        agent_type=AgentType.ASSISTANT,
        trust_level=TrustLevel.DELEGATED,
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def ephemeral_agent(db_session: AsyncSession, root_agent: Agent) -> Agent:
    """Create an ephemeral agent."""
    agent = Agent(
        name="Ephemeral Agent",
        parent_agent_id=root_agent.id,
        agent_type=AgentType.TOOL,
        trust_level=TrustLevel.EPHEMERAL,
        status=AgentStatus.ACTIVE,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def root_agent_key(
    db_session: AsyncSession, root_agent: Agent
) -> tuple[Agent, str]:
    """Create API key for root agent."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["*"],
    )
    await db_session.commit()
    return root_agent, raw_key


@pytest_asyncio.fixture
async def delegated_agent_key(
    db_session: AsyncSession, delegated_agent: Agent
) -> tuple[Agent, str]:
    """Create API key for delegated agent."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=delegated_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["read"],
    )
    await db_session.commit()
    return delegated_agent, raw_key


@pytest_asyncio.fixture
async def ephemeral_agent_key(
    db_session: AsyncSession, ephemeral_agent: Agent
) -> tuple[Agent, str]:
    """Create API key for ephemeral agent."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=ephemeral_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["execute"],
    )
    await db_session.commit()
    return ephemeral_agent, raw_key


@pytest.mark.asyncio
class TestGetCurrentAgent:
    """Test get_current_agent dependency."""

    async def test_get_current_agent_with_valid_auth(
        self, root_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """get_current_agent should return agent from request state."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        @app.get("/test")
        async def test_endpoint(agent: CurrentAgent):
            return {"agent_id": str(agent.id), "name": agent.name}

        root_agent, raw_key = root_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/test", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == str(root_agent.id)
        assert data["name"] == root_agent.name

    async def test_get_current_agent_without_auth(self):
        """get_current_agent should raise 401 without authentication."""
        app = FastAPI()
        # Note: No middleware, so request.state.agent won't be set

        @app.get("/test")
        async def test_endpoint(agent: CurrentAgent):
            return {"agent_id": str(agent.id)}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/test")

        assert response.status_code == 401


@pytest.mark.asyncio
class TestRequireRootAgent:
    """Test require_root_agent dependency."""

    async def test_require_root_agent_with_root_agent(
        self, root_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """require_root_agent should allow root agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        @app.get("/admin")
        async def admin_endpoint(agent: RootAgent):
            return {"message": "root access granted", "agent_id": str(agent.id)}

        root_agent, raw_key = root_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/admin", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "root access granted"

    async def test_require_root_agent_with_delegated_agent(
        self, delegated_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """require_root_agent should deny delegated agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        @app.get("/admin")
        async def admin_endpoint(agent: RootAgent):
            return {"message": "root access granted"}

        delegated_agent, raw_key = delegated_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/admin", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 403
        problem = response.json()
        assert "detail" in problem
        # Check the nested detail structure
        detail = problem["detail"]
        assert detail["title"] == "Insufficient Privileges"
        assert detail["status"] == 403
        assert detail["required_trust_level"] == TrustLevel.ROOT.value
        assert detail["current_trust_level"] == TrustLevel.DELEGATED.value

    async def test_require_root_agent_with_ephemeral_agent(
        self, ephemeral_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """require_root_agent should deny ephemeral agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        @app.get("/admin")
        async def admin_endpoint(agent: RootAgent):
            return {"message": "root access granted"}

        ephemeral_agent, raw_key = ephemeral_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/admin", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 403


@pytest.mark.asyncio
class TestRequireTrustLevel:
    """Test require_trust_level dependency factory."""

    async def test_require_trust_level_root_allows_root(
        self, root_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """Root trust level requirement should allow root agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        from agentauth.dependencies import require_trust_level
        from typing import Annotated
        from fastapi import Depends

        @app.get("/sensitive")
        async def sensitive_endpoint(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.ROOT))]
        ):
            return {"access": "granted"}

        root_agent, raw_key = root_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/sensitive", headers={"X-Agent-Key": raw_key}
            )

        assert response.status_code == 200

    async def test_require_trust_level_root_denies_delegated(
        self, delegated_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """Root trust level requirement should deny delegated agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        from agentauth.dependencies import require_trust_level
        from typing import Annotated
        from fastapi import Depends

        @app.get("/sensitive")
        async def sensitive_endpoint(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.ROOT))]
        ):
            return {"access": "granted"}

        delegated_agent, raw_key = delegated_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/sensitive", headers={"X-Agent-Key": raw_key}
            )

        assert response.status_code == 403

    async def test_require_trust_level_delegated_allows_root_and_delegated(
        self, root_agent_key: tuple[Agent, str], delegated_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """Delegated trust level requirement should allow root and delegated agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        from agentauth.dependencies import require_trust_level
        from typing import Annotated
        from fastapi import Depends

        @app.get("/moderate")
        async def moderate_endpoint(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.DELEGATED))]
        ):
            return {"access": "granted", "trust_level": agent.trust_level.value}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Root agent should be allowed
            root_agent, root_key = root_agent_key
            response = await client.get("/moderate", headers={"X-Agent-Key": root_key})
            assert response.status_code == 200

            # Delegated agent should be allowed
            delegated_agent, delegated_key = delegated_agent_key
            response = await client.get(
                "/moderate", headers={"X-Agent-Key": delegated_key}
            )
            assert response.status_code == 200

    async def test_require_trust_level_delegated_denies_ephemeral(
        self, ephemeral_agent_key: tuple[Agent, str], test_session_maker: async_sessionmaker[AsyncSession]
    ):
        """Delegated trust level requirement should deny ephemeral agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        from agentauth.dependencies import require_trust_level
        from typing import Annotated
        from fastapi import Depends

        @app.get("/moderate")
        async def moderate_endpoint(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.DELEGATED))]
        ):
            return {"access": "granted"}

        ephemeral_agent, raw_key = ephemeral_agent_key

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/moderate", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 403
        problem = response.json()
        detail = problem["detail"]
        assert detail["required_trust_level"] == TrustLevel.DELEGATED.value
        assert detail["current_trust_level"] == TrustLevel.EPHEMERAL.value

    async def test_require_trust_level_ephemeral_allows_all(
        self,
        root_agent_key: tuple[Agent, str],
        delegated_agent_key: tuple[Agent, str],
        ephemeral_agent_key: tuple[Agent, str],
        test_session_maker: async_sessionmaker[AsyncSession],
    ):
        """Ephemeral trust level requirement should allow all agents."""
        app = FastAPI()
        app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

        from agentauth.dependencies import require_trust_level
        from typing import Annotated
        from fastapi import Depends

        @app.get("/open")
        async def open_endpoint(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.EPHEMERAL))]
        ):
            return {"access": "granted"}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # All agents should be allowed
            for agent, raw_key in [
                root_agent_key,
                delegated_agent_key,
                ephemeral_agent_key,
            ]:
                response = await client.get("/open", headers={"X-Agent-Key": raw_key})
                assert response.status_code == 200
