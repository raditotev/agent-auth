"""Pytest configuration and fixtures."""

import os

# Set admin key for tests (must be before agentauth imports so config picks it up)
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

from collections.abc import AsyncGenerator
from typing import Any

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from agentauth.core.database import BaseModel, get_session
from agentauth.main import create_app
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.signing_key import KeyAlgorithm, SigningKey
from agentauth.services.crypto import CryptoService


# Test database URL — override via TEST_DATABASE_URL env var to match your environment
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://agentauth:agentauth_dev_password@localhost:5432/agentauth_test",
)


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


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test HTTP client with database session override."""
    app = create_app()

    # Override the database session dependency
    async def override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session

    async with AsyncClient(
        transport=ASGITransport(app=app),  # type: ignore
        base_url="http://test",
    ) as ac:
        yield ac

    # Clean up overrides
    app.dependency_overrides.clear()


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
