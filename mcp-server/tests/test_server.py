"""Unit tests for AgentAuth MCP server tools."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import agentauth_mcp.server as server_module
from agentauth_mcp.client import AgentAuthHTTPClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(**method_returns: dict) -> MagicMock:
    """Create a mock AgentAuthHTTPClient with specified async return values."""
    mock = MagicMock(spec=AgentAuthHTTPClient)
    for method, return_value in method_returns.items():
        setattr(mock, method, AsyncMock(return_value=return_value))
    return mock


# ---------------------------------------------------------------------------
# _get_client tests
# ---------------------------------------------------------------------------


class TestGetClient:
    def setup_method(self) -> None:
        # Reset singleton before each test
        server_module._client = None

    def teardown_method(self) -> None:
        server_module._client = None

    def test_get_client_raises_without_env_var(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AGENTAUTH_URL", None)
            with pytest.raises(RuntimeError, match="AGENTAUTH_URL"):
                server_module._get_client()

    def test_get_client_creates_client_with_env_url(self) -> None:
        with patch.dict(os.environ, {"AGENTAUTH_URL": "http://example.com"}):
            client = server_module._get_client()
            assert isinstance(client, AgentAuthHTTPClient)
            assert client.base_url == "http://example.com"

    def test_get_client_returns_singleton(self) -> None:
        with patch.dict(os.environ, {"AGENTAUTH_URL": "http://example.com"}):
            c1 = server_module._get_client()
            c2 = server_module._get_client()
            assert c1 is c2

    def test_get_client_respects_existing_singleton(self) -> None:
        existing = MagicMock(spec=AgentAuthHTTPClient)
        server_module._client = existing
        result = server_module._get_client()
        assert result is existing


class TestDefaultApiKey:
    def test_returns_env_var_value(self) -> None:
        with patch.dict(os.environ, {"AGENTAUTH_API_KEY": "my-key"}):
            assert server_module._default_api_key() == "my-key"

    def test_returns_none_when_not_set(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "AGENTAUTH_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            assert server_module._default_api_key() is None


# ---------------------------------------------------------------------------
# Tool: discover
# ---------------------------------------------------------------------------


class TestDiscoverTool:
    @pytest.mark.asyncio
    async def test_discover_calls_client_discover(self) -> None:
        expected = {"issuer": "http://localhost:8000"}
        mock_client = _make_mock_client(discover=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.discover()

        mock_client.discover.assert_awaited_once()
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: quickstart
# ---------------------------------------------------------------------------


class TestQuickstartTool:
    @pytest.mark.asyncio
    async def test_quickstart_passes_args_to_client(self) -> None:
        expected = {
            "agent": {"id": "uuid"},
            "api_key": "raw-key",
            "access_token": "tok",
            "refresh_token": "rt",
            "token_type": "Bearer",
            "expires_in": 900,
            "expires_at": "2026-01-01T00:15:00Z",
            "refresh_before": "2026-01-01T00:14:00Z",
        }
        mock_client = _make_mock_client(quickstart=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.quickstart("my-agent", "orchestrator", "desc")

        mock_client.quickstart.assert_awaited_once_with("my-agent", "orchestrator", "desc")
        assert result == expected

    @pytest.mark.asyncio
    async def test_quickstart_without_description(self) -> None:
        mock_client = _make_mock_client(quickstart={})

        with patch.object(server_module, "_get_client", return_value=mock_client):
            await server_module.quickstart("my-agent", "tool")

        mock_client.quickstart.assert_awaited_once_with("my-agent", "tool", None)

    @pytest.mark.asyncio
    async def test_quickstart_returns_http_error_dict(self) -> None:
        error_response = MagicMock()
        error_response.status_code = 422
        error_response.json.return_value = {"detail": "Validation error"}
        mock_client = MagicMock(spec=AgentAuthHTTPClient)
        mock_client.quickstart = AsyncMock(
            side_effect=httpx.HTTPStatusError("422", request=MagicMock(), response=error_response)
        )

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.quickstart("bad", "unknown")

        assert result["status_code"] == 422
        assert "error" in result


# ---------------------------------------------------------------------------
# Tool: list_agents
# ---------------------------------------------------------------------------


class TestListAgentsTool:
    @pytest.mark.asyncio
    async def test_list_agents_passes_pagination(self) -> None:
        expected = {"data": [], "meta": {"total": 0}}
        mock_client = _make_mock_client(list_agents=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.list_agents("my-token", limit=10, offset=5)

        mock_client.list_agents.assert_awaited_once_with(auth="my-token", limit=10, offset=5)
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: get_agent
# ---------------------------------------------------------------------------


class TestGetAgentTool:
    @pytest.mark.asyncio
    async def test_get_agent_passes_id_and_token(self) -> None:
        expected = {"id": "agent-uuid", "name": "my-agent"}
        mock_client = _make_mock_client(get_agent=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.get_agent("agent-uuid", "my-token")

        mock_client.get_agent.assert_awaited_once_with("agent-uuid", auth="my-token")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: authenticate
# ---------------------------------------------------------------------------


class TestAuthenticateTool:
    @pytest.mark.asyncio
    async def test_authenticate_with_explicit_api_key(self) -> None:
        expected = {"access_token": "tok"}
        mock_client = _make_mock_client(authenticate=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.authenticate(api_key="my-key", scopes=["api.read"])

        mock_client.authenticate.assert_awaited_once_with("my-key", ["api.read"])
        assert result == expected

    @pytest.mark.asyncio
    async def test_authenticate_falls_back_to_env_var(self) -> None:
        expected = {"access_token": "tok"}
        mock_client = _make_mock_client(authenticate=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            with patch.object(server_module, "_default_api_key", return_value="env-key"):
                result = await server_module.authenticate()

        mock_client.authenticate.assert_awaited_once_with("env-key", None)
        assert result == expected

    @pytest.mark.asyncio
    async def test_authenticate_returns_error_when_no_key(self) -> None:
        mock_client = _make_mock_client()

        with patch.object(server_module, "_get_client", return_value=mock_client):
            with patch.object(server_module, "_default_api_key", return_value=None):
                result = await server_module.authenticate()

        assert "error" in result
        mock_client.authenticate.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticate_without_scopes(self) -> None:
        mock_client = _make_mock_client(authenticate={"access_token": "tok"})

        with patch.object(server_module, "_get_client", return_value=mock_client):
            await server_module.authenticate(api_key="key")

        mock_client.authenticate.assert_awaited_once_with("key", None)


# ---------------------------------------------------------------------------
# Tool: refresh_token
# ---------------------------------------------------------------------------


class TestRefreshTokenTool:
    @pytest.mark.asyncio
    async def test_refresh_token_passes_value(self) -> None:
        expected = {"access_token": "new-tok", "refresh_token": "new-rt"}
        mock_client = _make_mock_client(refresh_token=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.refresh_token("old-rt")

        mock_client.refresh_token.assert_awaited_once_with("old-rt")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: introspect_token
# ---------------------------------------------------------------------------


class TestIntrospectTokenTool:
    @pytest.mark.asyncio
    async def test_introspect_token_passes_token(self) -> None:
        expected = {"active": True, "sub": "agent-uuid"}
        mock_client = _make_mock_client(introspect_token=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.introspect_token("some.jwt")

        mock_client.introspect_token.assert_awaited_once_with("some.jwt")
        assert result == expected

    @pytest.mark.asyncio
    async def test_introspect_token_inactive(self) -> None:
        expected = {"active": False}
        mock_client = _make_mock_client(introspect_token=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.introspect_token("expired.jwt")

        assert result["active"] is False


# ---------------------------------------------------------------------------
# Tool: revoke_token
# ---------------------------------------------------------------------------


class TestRevokeTokenTool:
    @pytest.mark.asyncio
    async def test_revoke_token_passes_token(self) -> None:
        expected = {"ok": True}
        mock_client = _make_mock_client(revoke_token=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.revoke_token("some.jwt")

        mock_client.revoke_token.assert_awaited_once_with("some.jwt")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: create_credential
# ---------------------------------------------------------------------------


class TestCreateCredentialTool:
    @pytest.mark.asyncio
    async def test_create_credential_passes_args(self) -> None:
        expected = {"id": "cred-uuid", "raw_key": "aa_secretkey"}
        mock_client = _make_mock_client(create_credential=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.create_credential(
                "agent-uuid", "my-token", scopes=["api.read"]
            )

        mock_client.create_credential.assert_awaited_once_with(
            "agent-uuid", auth="my-token", scopes=["api.read"]
        )
        assert result == expected

    @pytest.mark.asyncio
    async def test_create_credential_without_scopes(self) -> None:
        mock_client = _make_mock_client(create_credential={})

        with patch.object(server_module, "_get_client", return_value=mock_client):
            await server_module.create_credential("agent-uuid", "tok")

        mock_client.create_credential.assert_awaited_once_with(
            "agent-uuid", auth="tok", scopes=None
        )


# ---------------------------------------------------------------------------
# Tool: rotate_credential
# ---------------------------------------------------------------------------


class TestRotateCredentialTool:
    @pytest.mark.asyncio
    async def test_rotate_credential_passes_args(self) -> None:
        expected = {"id": "cred-uuid", "raw_key": "new_key"}
        mock_client = _make_mock_client(rotate_credential=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.rotate_credential("cred-uuid", "tok")

        mock_client.rotate_credential.assert_awaited_once_with("cred-uuid", auth="tok")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: revoke_credential
# ---------------------------------------------------------------------------


class TestRevokeCredentialTool:
    @pytest.mark.asyncio
    async def test_revoke_credential_passes_args(self) -> None:
        expected = {"ok": True}
        mock_client = _make_mock_client(revoke_credential=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.revoke_credential("cred-uuid", "tok")

        mock_client.revoke_credential.assert_awaited_once_with("cred-uuid", auth="tok")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool: create_delegation
# ---------------------------------------------------------------------------


class TestCreateDelegationTool:
    @pytest.mark.asyncio
    async def test_create_delegation_passes_all_args(self) -> None:
        expected = {"id": "del-uuid"}
        mock_client = _make_mock_client(create_delegation=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.create_delegation(
                delegate_agent_id="delegate-uuid",
                scopes=["api.read", "agents.write"],
                access_token="tok",
                max_chain_depth=2,
                expires_in_hours=48,
            )

        mock_client.create_delegation.assert_awaited_once_with(
            delegate_agent_id="delegate-uuid",
            scopes=["api.read", "agents.write"],
            auth="tok",
            max_chain_depth=2,
            expires_in_hours=48,
        )
        assert result == expected

    @pytest.mark.asyncio
    async def test_create_delegation_defaults(self) -> None:
        mock_client = _make_mock_client(create_delegation={})

        with patch.object(server_module, "_get_client", return_value=mock_client):
            await server_module.create_delegation(
                delegate_agent_id="delegate-uuid",
                scopes=["api.read"],
                access_token="tok",
            )

        mock_client.create_delegation.assert_awaited_once_with(
            delegate_agent_id="delegate-uuid",
            scopes=["api.read"],
            auth="tok",
            max_chain_depth=3,
            expires_in_hours=None,
        )


# ---------------------------------------------------------------------------
# Tool: check_permission
# ---------------------------------------------------------------------------


class TestCheckPermissionTool:
    @pytest.mark.asyncio
    async def test_check_permission_passes_all_args(self) -> None:
        expected = {"allowed": True, "effect": "allow"}
        mock_client = _make_mock_client(check_permission=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.check_permission(
                agent_id="agent-uuid",
                action="read",
                resource="/api/v1/credentials",
                access_token="tok",
            )

        mock_client.check_permission.assert_awaited_once_with(
            agent_id="agent-uuid",
            action="read",
            resource="/api/v1/credentials",
            auth="tok",
        )
        assert result == expected

    @pytest.mark.asyncio
    async def test_check_permission_denied(self) -> None:
        expected = {"allowed": False, "effect": "deny"}
        mock_client = _make_mock_client(check_permission=expected)

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.check_permission(
                agent_id="agent-uuid",
                action="delete",
                resource="/api/v1/credentials",
                access_token="tok",
            )

        assert result["allowed"] is False


# ---------------------------------------------------------------------------
# HTTP error handling — cross-cutting concern
# ---------------------------------------------------------------------------


def _http_error_side_effect(status_code: int, detail: object = "error") -> httpx.HTTPStatusError:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"detail": detail}
    return httpx.HTTPStatusError(str(status_code), request=MagicMock(), response=resp)


class TestHttpErrorHandling:
    @pytest.mark.asyncio
    async def test_authenticate_returns_error_dict_on_401(self) -> None:
        mock_client = MagicMock(spec=AgentAuthHTTPClient)
        mock_client.authenticate = AsyncMock(side_effect=_http_error_side_effect(401))

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.authenticate(api_key="bad-key")

        assert result["status_code"] == 401
        assert "error" in result

    @pytest.mark.asyncio
    async def test_get_agent_returns_error_dict_on_404(self) -> None:
        mock_client = MagicMock(spec=AgentAuthHTTPClient)
        mock_client.get_agent = AsyncMock(side_effect=_http_error_side_effect(404, "Not found"))

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.get_agent("missing-id", "tok")

        assert result["status_code"] == 404
        assert "error" in result

    @pytest.mark.asyncio
    async def test_create_credential_returns_error_dict_on_403(self) -> None:
        mock_client = MagicMock(spec=AgentAuthHTTPClient)
        mock_client.create_credential = AsyncMock(side_effect=_http_error_side_effect(403))

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.create_credential("agent-id", "tok")

        assert result["status_code"] == 403
        assert "error" in result

    @pytest.mark.asyncio
    async def test_check_permission_returns_error_dict_on_500(self) -> None:
        mock_client = MagicMock(spec=AgentAuthHTTPClient)
        mock_client.check_permission = AsyncMock(side_effect=_http_error_side_effect(500))

        with patch.object(server_module, "_get_client", return_value=mock_client):
            result = await server_module.check_permission(
                agent_id="id", action="read", resource="/res", access_token="tok"
            )

        assert result["status_code"] == 500
        assert "error" in result
