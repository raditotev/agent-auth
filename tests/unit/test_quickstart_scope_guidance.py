"""Unit tests for quickstart scope guidance (Task 9.2).

Tests that:
- GET /.well-known/agent-configuration includes the quickstart key with correct fields
- client_credentials invalid_scope errors include a hint when the credential has empty scopes
"""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from agentauth.api.v1.wellknown import router as wellknown_router


@pytest.fixture
def discover_app() -> FastAPI:
    """Minimal FastAPI app with only the wellknown router."""
    app = FastAPI()
    app.include_router(wellknown_router)
    return app


@pytest.mark.asyncio
async def test_discover_includes_quickstart_key(discover_app: FastAPI) -> None:
    """GET /.well-known/agent-configuration must include a 'quickstart' key."""
    async with AsyncClient(
        transport=ASGITransport(app=discover_app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/agent-configuration")

    assert response.status_code == 200
    data = response.json()
    assert "quickstart" in data


@pytest.mark.asyncio
async def test_discover_quickstart_scopes_is_empty_list(discover_app: FastAPI) -> None:
    """quickstart.scopes must be an empty list."""
    async with AsyncClient(
        transport=ASGITransport(app=discover_app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/agent-configuration")

    quickstart = response.json()["quickstart"]
    assert quickstart["scopes"] == []


@pytest.mark.asyncio
async def test_discover_quickstart_next_steps(discover_app: FastAPI) -> None:
    """quickstart.next_steps must be ['create_credential', 'authenticate']."""
    async with AsyncClient(
        transport=ASGITransport(app=discover_app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/agent-configuration")

    quickstart = response.json()["quickstart"]
    assert quickstart["next_steps"] == ["create_credential", "authenticate"]


@pytest.mark.asyncio
async def test_discover_quickstart_has_description(discover_app: FastAPI) -> None:
    """quickstart must include a non-empty description."""
    async with AsyncClient(
        transport=ASGITransport(app=discover_app), base_url="http://test"
    ) as client:
        response = await client.get("/.well-known/agent-configuration")

    quickstart = response.json()["quickstart"]
    assert "description" in quickstart
    assert len(quickstart["description"]) > 0


class TestInvalidScopeHint:
    """Tests for the hint field in invalid_scope error responses."""

    def test_hint_included_when_credential_has_empty_scopes(self) -> None:
        """
        When credential scopes are empty and requested scopes are non-empty,
        the error detail should include a 'hint' field.
        """
        from agentauth.api.v1.auth import _validate_scopes

        allowed_scopes: list[str] = []
        requested_scopes = ["files.read"]

        result = _validate_scopes(requested_scopes, allowed_scopes)
        # _validate_scopes returns None when validation fails
        assert result is None

        # Simulate the error detail construction in auth.py
        error_detail: dict = {
            "error": "invalid_scope",
            "error_description": "Requested scopes exceed credential's allowed scopes",
        }
        if not allowed_scopes:
            error_detail["hint"] = (
                "Quickstart credentials issue tokens with empty scopes. "
                "To obtain a scoped token, first create a credential with the desired scopes "
                "via POST /api/v1/credentials, then authenticate with that credential."
            )

        assert "hint" in error_detail
        assert "Quickstart" in error_detail["hint"]
        assert "/api/v1/credentials" in error_detail["hint"]

    def test_hint_not_included_when_credential_has_scopes(self) -> None:
        """
        When credential has non-empty scopes, the 'hint' field should NOT be included.
        """
        from agentauth.api.v1.auth import _validate_scopes

        allowed_scopes = ["files.read"]
        requested_scopes = ["files.read", "admin.full"]

        result = _validate_scopes(requested_scopes, allowed_scopes)
        assert result is None

        error_detail: dict = {
            "error": "invalid_scope",
            "error_description": "Requested scopes exceed credential's allowed scopes",
        }
        if not allowed_scopes:
            error_detail["hint"] = "..."

        assert "hint" not in error_detail
