"""Unit tests for token expiry warning headers (Task 9.4)."""

import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from starlette.middleware.base import BaseHTTPMiddleware

from agentauth.api.middleware import AuthenticationMiddleware
from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.schemas.token import TokenClaims


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(agent_id=None) -> Agent:
    agent = Agent(
        name="Expiry Test Agent",
        agent_type=AgentType.ORCHESTRATOR,
        trust_level=TrustLevel.ROOT,
        status=AgentStatus.ACTIVE,
        max_child_depth=3,
    )
    agent.id = agent_id or uuid4()
    return agent


def _make_claims(exp: int, family_id: str | None = "fam-123") -> TokenClaims:
    return TokenClaims(
        iss="https://agentauth.test",
        sub=str(uuid4()),
        aud="https://agentauth.test",
        exp=exp,
        iat=int(time.time()) - 30,
        jti=str(uuid4()),
        scopes=["api.read"],
        agent_type=AgentType.ORCHESTRATOR,
        trust_level=TrustLevel.ROOT,
        family_id=family_id,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app_with_mock_auth() -> FastAPI:
    """App with AuthenticationMiddleware wired to a controllable verify mock."""
    app = FastAPI()

    @app.get("/protected")
    async def protected(request: Request):
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    return app


# ---------------------------------------------------------------------------
# Helper: build app with specific _verify_bearer_token behaviour
# ---------------------------------------------------------------------------


def _build_app(verify_result) -> FastAPI:
    """Return a FastAPI app whose bearer-token verify always returns *verify_result*."""
    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=verify_result)
    mw._verify_api_key = AsyncMock(return_value=None)

    # Wrap in a thin ASGI app so the middleware processes all requests
    from starlette.applications import Starlette
    from starlette.routing import Route

    async def _handler(scope, receive, send):
        await mw(scope, receive, send)

    return mw  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_x_token_expires_in_present_on_authenticated_request():
    """X-Token-Expires-In header must appear for authenticated Bearer requests."""
    agent = _make_agent()
    future_exp = int(time.time()) + 500
    claims = _make_claims(exp=future_exp)

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=(agent, ["api.read"], claims))
    mw._verify_api_key = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer fake-token"}
        )

    assert response.status_code == 200
    assert "x-token-expires-in" in response.headers
    remaining = int(response.headers["x-token-expires-in"])
    assert 490 <= remaining <= 510


@pytest.mark.asyncio
async def test_x_token_refresh_advised_present_when_below_threshold():
    """X-Token-Refresh-Advised: true must appear when remaining < warning threshold."""
    agent = _make_agent()
    # 60 seconds left — well below default threshold of 120
    future_exp = int(time.time()) + 60
    claims = _make_claims(exp=future_exp)

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=(agent, ["api.read"], claims))
    mw._verify_api_key = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer fake-token"}
        )

    assert response.status_code == 200
    assert response.headers.get("x-token-refresh-advised") == "true"


@pytest.mark.asyncio
async def test_x_token_refresh_advised_absent_when_above_threshold():
    """X-Token-Refresh-Advised must NOT appear when remaining > warning threshold."""
    agent = _make_agent()
    # 300 seconds left — above default threshold of 120
    future_exp = int(time.time()) + 300
    claims = _make_claims(exp=future_exp)

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=(agent, ["api.read"], claims))
    mw._verify_api_key = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer fake-token"}
        )

    assert response.status_code == 200
    assert "x-token-refresh-advised" not in response.headers


@pytest.mark.asyncio
async def test_x_token_expires_in_absent_on_unauthenticated_response():
    """X-Token-Expires-In must NOT appear on 401 responses."""
    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=None)
    mw._verify_api_key = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get(
            "/protected", headers={"Authorization": "Bearer invalid-token"}
        )

    assert response.status_code == 401
    assert "x-token-expires-in" not in response.headers
    assert "x-token-refresh-advised" not in response.headers


@pytest.mark.asyncio
async def test_x_token_expires_in_absent_on_exempt_paths():
    """Expiry headers must NOT appear on exempt (unauthenticated) paths."""
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    mw = AuthenticationMiddleware(app)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert "x-token-expires-in" not in response.headers


@pytest.mark.asyncio
async def test_x_token_expires_in_absent_for_api_key_auth():
    """X-Token-Expires-In must NOT appear when authenticated via API key (no JWT exp)."""
    agent = _make_agent()

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    # API key returns None as third tuple element (no JWT claims)
    mw._verify_api_key = AsyncMock(return_value=(agent, ["api.read"], None))
    mw._verify_bearer_token = AsyncMock(return_value=None)

    async with AsyncClient(transport=ASGITransport(app=mw), base_url="http://test") as client:
        response = await client.get("/protected", headers={"X-Agent-Key": "test-key"})

    assert response.status_code == 200
    assert "x-token-expires-in" not in response.headers


@pytest.mark.asyncio
async def test_expiry_warning_webhook_not_emitted_when_above_threshold():
    """No webhook task should be created when token still has plenty of time left."""
    agent = _make_agent()
    future_exp = int(time.time()) + 500
    claims = _make_claims(exp=future_exp, family_id="fam-abc")

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=(agent, ["api.read"], claims))
    mw._verify_api_key = AsyncMock(return_value=None)

    with patch("asyncio.create_task") as mock_create_task:
        async with AsyncClient(
            transport=ASGITransport(app=mw), base_url="http://test"
        ) as client:
            response = await client.get(
                "/protected", headers={"Authorization": "Bearer fake-token"}
            )

    assert response.status_code == 200
    mock_create_task.assert_not_called()


@pytest.mark.asyncio
async def test_expiry_warning_webhook_emitted_when_below_threshold():
    """A background task should be created for token.expiring_soon when near expiry."""
    agent = _make_agent()
    future_exp = int(time.time()) + 60
    claims = _make_claims(exp=future_exp, family_id="fam-xyz")

    app = FastAPI()

    @app.get("/protected")
    async def protected(_: Request):
        return {"ok": True}

    mw = AuthenticationMiddleware(app)
    mw._verify_bearer_token = AsyncMock(return_value=(agent, ["api.read"], claims))
    mw._verify_api_key = AsyncMock(return_value=None)

    # Return a no-op coroutine so the RuntimeWarning about unawaited coroutines is avoided
    async def _noop(*_args, **_kwargs):
        pass

    with patch("asyncio.create_task", side_effect=lambda coro: (coro.close(), None)) as mock_create_task:
        async with AsyncClient(
            transport=ASGITransport(app=mw), base_url="http://test"
        ) as client:
            response = await client.get(
                "/protected", headers={"Authorization": "Bearer fake-token"}
            )

    assert response.status_code == 200
    mock_create_task.assert_called_once()
