"""Pytest configuration and fixtures."""

import os

# Set admin key for tests (must be before agentauth imports so config picks it up)
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

from collections.abc import AsyncGenerator
from typing import Any

import asyncpg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from agentauth.core.database import BaseModel, get_session
from agentauth.main import create_app
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import CredentialType
from agentauth.models.signing_key import KeyAlgorithm, SigningKey
from agentauth.services.credential import CredentialService
from agentauth.services.crypto import CryptoService


# Test database URL — override via TEST_DATABASE_URL env var to match your environment
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://agentauth:agentauth_dev_password@localhost:5432/agentauth_test",
)

# Derive a plain asyncpg DSN pointing at the default DB (used to CREATE the test DB)
_dsn_without_db = TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://").rsplit("/", 1)[0]
_TEST_DB_NAME = TEST_DATABASE_URL.rsplit("/", 1)[-1]
_BASE_DSN = f"{_dsn_without_db}/postgres"


@pytest.fixture(scope="session", autouse=True)
def ensure_test_database() -> None:
    """Create the test database if it doesn't exist (handles tmpfs postgres restarts)."""
    import asyncio

    async def _create_db() -> None:
        conn = await asyncpg.connect(_BASE_DSN)
        try:
            await conn.execute(f'CREATE DATABASE "{_TEST_DB_NAME}"')
        except asyncpg.DuplicateDatabaseError:
            pass
        finally:
            await conn.close()

    asyncio.run(_create_db())


@pytest_asyncio.fixture(scope="function")
async def db_engine() -> AsyncGenerator[Any, None]:
    """Create a test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)

    yield engine

    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine: Any) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def auth_agent(db_session: AsyncSession) -> Agent:
    """Root agent used to authenticate the test HTTP client."""
    agent = Agent(
        parent_agent_id=None,
        name="test-client-auth-agent",
        agent_type=AgentType.TOOL,
        description="Auto-created agent for test client authentication",
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.ACTIVE,
        max_child_depth=5,
        agent_metadata={},
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def auth_child_agent(db_session: AsyncSession, auth_agent: Agent) -> Agent:
    """A child agent under auth_agent — useful for credential ownership tests."""
    agent = Agent(
        parent_agent_id=auth_agent.id,
        name="test-auth-child-agent",
        agent_type=AgentType.ASSISTANT,
        description="Child of auth agent",
        trust_level=TrustLevel.DELEGATED,
        status=AgentStatus.ACTIVE,
        max_child_depth=4,
        agent_metadata={},
    )
    db_session.add(agent)
    await db_session.flush()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture(scope="function")
async def client(
    db_engine: Any, db_session: AsyncSession, auth_agent: Agent
) -> AsyncGenerator[AsyncClient, None]:
    """Create a test HTTP client with database session override and agent authentication."""
    import agentauth.core.database as db_module
    from sqlalchemy.ext.asyncio import async_sessionmaker as _async_sessionmaker

    # Create a session maker from the test engine so the auth middleware uses test DB
    test_session_maker = _async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )

    # Patch the global session maker so AuthenticationMiddleware uses test DB
    original_session_maker = db_module.async_session_maker
    db_module.async_session_maker = test_session_maker

    credential_service = CredentialService(db_session)
    _, api_key = await credential_service.create_credential(
        agent_id=auth_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=[
            "agents.read", "agents.write", "credentials.read", "credentials.write",
            "delegations.read", "delegations.write", "audit.read",
            # admin.agents.list grants system-wide agent visibility (keeps existing tests passing)
            "admin.agents.list",
        ],
    )
    # Commit so the auth middleware's independent session can see the credential
    await db_session.commit()

    app = create_app()

    # Override the database session dependency for route handlers
    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore
        base_url="http://test",
        headers={"X-Agent-Key": api_key},
    ) as ac:
        yield ac

    # Clean up overrides and restore session maker
    app.dependency_overrides.clear()
    db_module.async_session_maker = original_session_maker


@pytest_asyncio.fixture(autouse=True)
async def flush_rate_limits() -> AsyncGenerator[None, None]:
    """Flush rate limit keys from Redis before each test to prevent cross-test contamination."""
    import redis.asyncio as aioredis

    from agentauth.config import settings

    try:
        # Create a fresh connection each time to avoid stale event loop issues
        r = aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
        cursor = 0
        while True:
            cursor, keys = await r.scan(cursor, match="ratelimit:*", count=100)
            if keys:
                await r.delete(*keys)
            if cursor == 0:
                break
        await r.aclose()
    except Exception:
        pass  # Redis might not be available in all environments
    yield


@pytest_asyncio.fixture
async def root_agent(db_session: AsyncSession) -> Agent:
    """Create a root agent for testing."""
    agent = Agent(
        parent_agent_id=None,
        name="test-root-agent",
        agent_type=AgentType.ORCHESTRATOR,
        description="Test root agent",
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.ACTIVE,
        max_child_depth=3,
        agent_metadata={"test": True},
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def child_agent(db_session: AsyncSession, root_agent: Agent) -> Agent:
    """Create a child agent for testing."""
    agent = Agent(
        parent_agent_id=root_agent.id,
        name="test-child-agent",
        agent_type=AgentType.ASSISTANT,
        description="Test child agent",
        trust_level=TrustLevel.DELEGATED,
        status=AgentStatus.ACTIVE,
        max_child_depth=2,
        agent_metadata={"test": True},
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def signing_key_rsa(db_session: AsyncSession) -> SigningKey:
    """Create an RSA signing key for testing."""
    crypto_service = CryptoService(db_session)
    signing_key = await crypto_service.generate_rsa_key_pair()
    db_session.add(signing_key)
    await db_session.commit()
    await db_session.refresh(signing_key)
    return signing_key


@pytest_asyncio.fixture
async def signing_key_ecdsa(db_session: AsyncSession) -> SigningKey:
    """Create an ECDSA signing key for testing."""
    crypto_service = CryptoService(db_session)
    signing_key = await crypto_service.generate_ecdsa_key_pair()
    db_session.add(signing_key)
    await db_session.commit()
    await db_session.refresh(signing_key)
    return signing_key
