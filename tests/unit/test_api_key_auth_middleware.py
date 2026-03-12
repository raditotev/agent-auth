"""Unit tests for API key authentication middleware."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.api.middleware import AuthenticationMiddleware
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import Credential, CredentialType
from agentauth.services.credential import CredentialService


@pytest_asyncio.fixture
async def test_app(db_engine) -> FastAPI:
    """Create a test FastAPI app with authentication middleware."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    app = FastAPI()

    # Create session maker for test database
    test_session_maker = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Add authentication middleware with test session maker
    app.add_middleware(AuthenticationMiddleware, session_maker=test_session_maker)

    # Public endpoint (no auth required)
    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    # Protected endpoint (requires auth)
    @app.get("/protected")
    async def protected(request: Request):
        agent = request.state.agent
        return {
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "trust_level": agent.trust_level.value,
        }

    # Another protected endpoint
    @app.post("/api/v1/agents")
    async def create_agent(request: Request):
        agent = request.state.agent
        return {"created_by": str(agent.id)}

    return app


@pytest_asyncio.fixture
async def test_agent(db_session: AsyncSession) -> Agent:
    """Create a test root agent."""
    agent = Agent(
        name="Test Agent",
        agent_type=AgentType.ORCHESTRATOR,
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.ACTIVE,
        description="Test agent for middleware tests",
        max_child_depth=3,
        agent_metadata={"test": True},
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def inactive_agent(db_session: AsyncSession) -> Agent:
    """Create an inactive test agent."""
    agent = Agent(
        name="Inactive Agent",
        agent_type=AgentType.ORCHESTRATOR,
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.SUSPENDED,
        description="Inactive test agent",
        deactivated_at=datetime.now(UTC),
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def valid_credential(db_session: AsyncSession, test_agent: Agent) -> tuple[Credential, str]:
    """Create a valid API key credential for the test agent."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=test_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["read", "write"],
    )
    await db_session.commit()
    return credential, raw_key


@pytest_asyncio.fixture
async def expired_credential(db_session: AsyncSession, test_agent: Agent) -> tuple[Credential, str]:
    """Create an expired API key credential."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=test_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["read"],
        expires_at=datetime.now(UTC) - timedelta(days=1),  # Already expired
    )
    await db_session.commit()
    return credential, raw_key


@pytest_asyncio.fixture
async def revoked_credential(db_session: AsyncSession, test_agent: Agent) -> tuple[Credential, str]:
    """Create a revoked API key credential."""
    credential_service = CredentialService(db_session)
    credential, raw_key = await credential_service.create_credential(
        agent_id=test_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["read"],
    )
    # Revoke it
    await credential_service.revoke_credential(credential.id)
    await db_session.commit()
    return credential, raw_key


@pytest.mark.asyncio
class TestAuthenticationMiddleware:
    """Test suite for authentication middleware."""

    async def test_health_endpoint_no_auth_required(self, test_app: FastAPI):
        """Health endpoint should not require authentication."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    async def test_protected_endpoint_without_auth(self, test_app: FastAPI):
        """Protected endpoint should return 401 without API key."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected")

        assert response.status_code == 401
        assert response.headers["content-type"] == "application/problem+json"

        problem = response.json()
        assert problem["type"] == "https://agentauth.dev/problems/authentication-failed"
        assert problem["title"] == "Missing Authentication"
        assert problem["status"] == 401
        assert "X-Agent-Key header" in problem["detail"]
        assert problem["instance"] == "/protected"

    async def test_protected_endpoint_with_valid_auth(
        self,
        test_app: FastAPI,
        valid_credential: tuple[Credential, str],
        test_agent: Agent,
    ):
        """Protected endpoint should work with valid API key."""
        credential, raw_key = valid_credential

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == str(test_agent.id)
        assert data["agent_name"] == test_agent.name
        assert data["trust_level"] == TrustLevel.ROOT.value

    async def test_protected_endpoint_with_invalid_api_key(self, test_app: FastAPI):
        """Protected endpoint should return 401 with invalid API key."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get(
                "/protected", headers={"X-Agent-Key": "invalid_key_12345678"}
            )

        assert response.status_code == 401
        problem = response.json()
        assert problem["title"] == "Invalid Authentication"
        assert "invalid, expired, or revoked" in problem["detail"]

    async def test_protected_endpoint_with_expired_credential(
        self,
        test_app: FastAPI,
        expired_credential: tuple[Credential, str],
    ):
        """Protected endpoint should return 401 with expired credential."""
        credential, raw_key = expired_credential

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 401
        problem = response.json()
        assert problem["title"] == "Invalid Authentication"

    async def test_protected_endpoint_with_revoked_credential(
        self,
        test_app: FastAPI,
        revoked_credential: tuple[Credential, str],
    ):
        """Protected endpoint should return 401 with revoked credential."""
        credential, raw_key = revoked_credential

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 401
        problem = response.json()
        assert problem["title"] == "Invalid Authentication"

    async def test_protected_endpoint_with_inactive_agent(
        self,
        test_app: FastAPI,
        db_session: AsyncSession,
        inactive_agent: Agent,
    ):
        """Protected endpoint should return 401 with inactive agent."""
        # Create credential for inactive agent
        credential_service = CredentialService(db_session)
        credential, raw_key = await credential_service.create_credential(
            agent_id=inactive_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["read"],
        )
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 401
        problem = response.json()
        assert problem["title"] == "Agent Inactive"
        assert "suspended" in problem["detail"]

    async def test_last_used_at_recorded_in_redis_on_successful_auth(
        self,
        test_app: FastAPI,
        db_session: AsyncSession,
        valid_credential: tuple[Credential, str],
    ):
        """Credential usage should be recorded in Redis for deferred DB flush."""
        credential, raw_key = valid_credential

        # Make authenticated request
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 200

        # last_used_at is now deferred to Redis + background flush,
        # so it should NOT be updated synchronously in the DB
        await db_session.refresh(credential)

        # Verify usage was recorded in Redis instead
        from agentauth.core.redis import get_redis_client

        redis_client = get_redis_client()
        redis_value = await redis_client.get(f"cred_last_used:{credential.id}")
        assert redis_value is not None

    async def test_multiple_requests_with_same_credential(
        self,
        test_app: FastAPI,
        db_session: AsyncSession,
        valid_credential: tuple[Credential, str],
        test_agent: Agent,
    ):
        """Multiple requests with same credential should all succeed."""
        credential, raw_key = valid_credential

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            # Make 3 requests
            for _ in range(3):
                response = await client.get("/protected", headers={"X-Agent-Key": raw_key})
                assert response.status_code == 200
                data = response.json()
                assert data["agent_id"] == str(test_agent.id)

        # last_used_at is now deferred via Redis + background flush
        # Verify all requests succeeded (the important part)
        await db_session.refresh(credential)

    async def test_bootstrap_endpoint_exempt_from_auth(self, test_app: FastAPI):
        """Bootstrap endpoint should be accessible without authentication."""
        # Note: This test just verifies the endpoint is exempt from auth.
        # The actual bootstrap logic is tested elsewhere.
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            # This should not return 401 (missing auth)
            # It might return 404 or 405 since we didn't implement the endpoint in test_app
            response = await client.post("/api/v1/agents/bootstrap")

        # Should NOT be 401 (missing auth) - anything else is fine for this test
        assert response.status_code != 401

    async def test_request_state_injection(
        self,
        test_app: FastAPI,
        valid_credential: tuple[Credential, str],
        test_agent: Agent,
    ):
        """Middleware should inject agent into request.state."""
        credential, raw_key = valid_credential

        # Add endpoint that checks request.state
        @test_app.get("/check-state")
        async def check_state(request: Request):
            assert hasattr(request.state, "agent")
            assert hasattr(request.state, "agent_id")
            assert hasattr(request.state, "trust_level")
            assert request.state.agent.id == test_agent.id
            assert request.state.agent_id == test_agent.id
            assert request.state.trust_level == TrustLevel.ROOT
            return {"ok": True}

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/check-state", headers={"X-Agent-Key": raw_key})

        assert response.status_code == 200
        assert response.json() == {"ok": True}

    async def test_www_authenticate_header_on_401(self, test_app: FastAPI):
        """401 responses should include WWW-Authenticate header."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected")

        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers
        assert response.headers["WWW-Authenticate"] == 'ApiKey realm="AgentAuth"'

    async def test_rfc7807_problem_details_format(self, test_app: FastAPI):
        """401 responses should follow RFC 7807 Problem Details format."""
        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            response = await client.get("/protected")

        assert response.status_code == 401
        assert response.headers["content-type"] == "application/problem+json"

        problem = response.json()

        # Required fields per RFC 7807
        assert "type" in problem
        assert "title" in problem
        assert "status" in problem
        assert problem["status"] == 401

        # Our additional fields
        assert "detail" in problem
        assert "instance" in problem
        assert problem["instance"] == "/protected"
