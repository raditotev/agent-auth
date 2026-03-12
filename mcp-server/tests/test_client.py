"""Unit tests for AgentAuthHTTPClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agentauth_mcp.client import AgentAuthHTTPClient


@pytest.fixture
def client() -> AgentAuthHTTPClient:
    return AgentAuthHTTPClient("http://localhost:8000")


@pytest.fixture
def mock_response() -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    return resp


class TestAgentAuthHTTPClientInit:
    def test_strips_trailing_slash(self) -> None:
        c = AgentAuthHTTPClient("http://localhost:8000/")
        assert c.base_url == "http://localhost:8000"

    def test_stores_base_url(self) -> None:
        c = AgentAuthHTTPClient("http://example.com")
        assert c.base_url == "http://example.com"


class TestAuthHeaders:
    def test_bearer_token_takes_precedence(self, client: AgentAuthHTTPClient) -> None:
        headers = client._auth_headers(api_key="key123", token="tok456")
        assert headers == {"Authorization": "Bearer tok456"}

    def test_api_key_header(self, client: AgentAuthHTTPClient) -> None:
        headers = client._auth_headers(api_key="key123")
        assert headers == {"X-Agent-Key": "key123"}

    def test_no_credentials_returns_empty(self, client: AgentAuthHTTPClient) -> None:
        headers = client._auth_headers()
        assert headers == {}

    def test_token_only(self, client: AgentAuthHTTPClient) -> None:
        headers = client._auth_headers(token="mytoken")
        assert headers == {"Authorization": "Bearer mytoken"}


class TestRequestHelper:
    @pytest.mark.asyncio
    async def test_returns_json_on_200(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "value"}

        with patch.object(client._http, "request", new=AsyncMock(return_value=mock_response)):
            result = await client._request("GET", "/test")

        assert result == {"data": "value"}

    @pytest.mark.asyncio
    async def test_returns_ok_true_on_204(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.status_code = 204

        with patch.object(client._http, "request", new=AsyncMock(return_value=mock_response)):
            result = await client._request("DELETE", "/test")

        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_raises_on_http_error(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=mock_response
        )

        with patch.object(client._http, "request", new=AsyncMock(return_value=mock_response)):
            with pytest.raises(httpx.HTTPStatusError):
                await client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_builds_correct_url(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client._request("GET", "/api/v1/agents")

        call_kwargs = http_mock.call_args
        assert call_kwargs.args[1] == "http://localhost:8000/api/v1/agents"


class TestDiscover:
    @pytest.mark.asyncio
    async def test_discover_calls_well_known_endpoint(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        expected = {"issuer": "http://localhost:8000", "grant_types_supported": ["client_credentials"]}
        mock_response.json.return_value = expected
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.discover()

        assert result == expected
        http_mock.assert_called_once()
        assert "/.well-known/agent-configuration" in http_mock.call_args.args[1]


class TestAuthenticate:
    @pytest.mark.asyncio
    async def test_authenticate_sends_client_credentials_grant(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"access_token": "tok", "token_type": "bearer"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.authenticate("my-api-key")

        assert result["access_token"] == "tok"
        body = http_mock.call_args.kwargs["json"]
        assert body["grant_type"] == "client_credentials"
        assert body["client_secret"] == "my-api-key"

    @pytest.mark.asyncio
    async def test_authenticate_with_scopes(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"access_token": "tok"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.authenticate("my-api-key", scopes=["api.read", "agents.write"])

        body = http_mock.call_args.kwargs["json"]
        assert body["scope"] == "api.read agents.write"

    @pytest.mark.asyncio
    async def test_authenticate_without_scopes_omits_scope_field(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"access_token": "tok"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.authenticate("my-api-key", scopes=None)

        body = http_mock.call_args.kwargs["json"]
        assert "scope" not in body


class TestRefreshToken:
    @pytest.mark.asyncio
    async def test_refresh_token_sends_correct_grant(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"access_token": "new-tok", "refresh_token": "new-rt"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.refresh_token("old-refresh-token")

        assert result["access_token"] == "new-tok"
        body = http_mock.call_args.kwargs["json"]
        assert body["grant_type"] == "refresh_token"
        assert body["refresh_token"] == "old-refresh-token"


class TestIntrospectToken:
    @pytest.mark.asyncio
    async def test_introspect_sends_form_data(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"active": True, "sub": "agent-uuid"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.introspect_token("some.jwt.token")

        assert result["active"] is True
        data = http_mock.call_args.kwargs["data"]
        assert data == {"token": "some.jwt.token"}


class TestRevokeToken:
    @pytest.mark.asyncio
    async def test_revoke_sends_form_data(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.revoke_token("some.jwt.token")

        data = http_mock.call_args.kwargs["data"]
        assert data == {"token": "some.jwt.token"}


class TestQuickstart:
    @pytest.mark.asyncio
    async def test_quickstart_sends_required_fields(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "agent": {"id": "uuid", "name": "my-agent"},
            "api_key": "key",
            "api_key_prefix": "key",
            "token": {
                "access_token": "tok",
                "refresh_token": "rt",
                "token_type": "Bearer",
                "expires_in": 900,
                "expires_at": "2026-01-01T00:15:00Z",
                "refresh_before": "2026-01-01T00:14:00Z",
            },
            "message": "Agent registered successfully.",
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.quickstart("my-agent", "orchestrator")

        assert result["api_key"] == "key"
        body = http_mock.call_args.kwargs["json"]
        assert body["name"] == "my-agent"
        assert body["agent_type"] == "orchestrator"

    @pytest.mark.asyncio
    async def test_quickstart_flattens_token_fields(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "agent": {"id": "uuid"},
            "api_key": "key",
            "token": {
                "access_token": "tok",
                "refresh_token": "rt",
                "token_type": "Bearer",
                "expires_in": 900,
                "expires_at": "2026-01-01T00:15:00Z",
                "refresh_before": "2026-01-01T00:14:00Z",
            },
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.quickstart("my-agent", "orchestrator")

        assert result["access_token"] == "tok"
        assert result["refresh_token"] == "rt"
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 900
        assert result["expires_at"] == "2026-01-01T00:15:00Z"
        assert result["refresh_before"] == "2026-01-01T00:14:00Z"
        assert "token" not in result

    @pytest.mark.asyncio
    async def test_quickstart_omits_none_description(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"agent": {}, "api_key": "k", "token": {}}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.quickstart("my-agent", "tool")

        body = http_mock.call_args.kwargs["json"]
        assert "description" not in body

    @pytest.mark.asyncio
    async def test_quickstart_with_description(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"agent": {}, "api_key": "k", "token": {}}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.quickstart("my-agent", "tool", description="A tool agent")

        body = http_mock.call_args.kwargs["json"]
        assert body["description"] == "A tool agent"


class TestCreateCredential:
    @pytest.mark.asyncio
    async def test_create_credential_sends_agent_id_and_type(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "credential": {"id": "cred-uuid", "prefix": "aa_abc123", "agent_id": "agent-uuid"},
            "raw_key": "aa_secretkey",
            "message": "Save the raw_key.",
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.create_credential("agent-uuid", auth="tok")

        body = http_mock.call_args.kwargs["json"]
        assert body["agent_id"] == "agent-uuid"
        assert body["type"] == "api_key"

    @pytest.mark.asyncio
    async def test_create_credential_flattens_envelope(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "credential": {"id": "cred-uuid", "prefix": "aa_abc123"},
            "raw_key": "aa_secretkey",
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.create_credential("agent-uuid", auth="tok")

        assert result["id"] == "cred-uuid"
        assert result["prefix"] == "aa_abc123"
        assert result["raw_key"] == "aa_secretkey"
        assert "credential" not in result

    @pytest.mark.asyncio
    async def test_create_credential_with_scopes(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"credential": {}, "raw_key": "k"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.create_credential("agent-uuid", auth="tok", scopes=["api.read"])

        body = http_mock.call_args.kwargs["json"]
        assert body["scopes"] == ["api.read"]

    @pytest.mark.asyncio
    async def test_create_credential_sends_bearer_token(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"credential": {}, "raw_key": "k"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.create_credential("agent-uuid", auth="my-token")

        headers = http_mock.call_args.kwargs["headers"]
        assert headers == {"Authorization": "Bearer my-token"}


class TestRotateCredential:
    @pytest.mark.asyncio
    async def test_rotate_calls_rotate_endpoint(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "old_credential": {"id": "old-uuid", "prefix": "old"},
            "new_credential": {"id": "new-uuid", "prefix": "new_prefix"},
            "raw_key": "new_raw_key",
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.rotate_credential("cred-uuid", auth="tok")

        url = http_mock.call_args.args[1]
        assert "/api/v1/credentials/cred-uuid/rotate" in url

    @pytest.mark.asyncio
    async def test_rotate_flattens_new_credential(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "old_credential": {"id": "old-uuid"},
            "new_credential": {"id": "new-uuid", "prefix": "new_prefix"},
            "raw_key": "new_raw_key",
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.rotate_credential("cred-uuid", auth="tok")

        assert result["id"] == "new-uuid"
        assert result["prefix"] == "new_prefix"
        assert result["raw_key"] == "new_raw_key"
        assert result["old_credential_id"] == "old-uuid"
        assert "new_credential" not in result
        assert "old_credential" not in result


class TestRevokeCredential:
    @pytest.mark.asyncio
    async def test_revoke_sends_delete_request(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.status_code = 204
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.revoke_credential("cred-uuid", auth="tok")

        assert result == {"ok": True}
        method = http_mock.call_args.args[0]
        assert method == "DELETE"
        url = http_mock.call_args.args[1]
        assert "/api/v1/credentials/cred-uuid" in url


class TestListAgents:
    @pytest.mark.asyncio
    async def test_list_agents_sends_pagination_params(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"data": [], "meta": {"total": 0}}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.list_agents(auth="tok", limit=10, offset=20)

        params = http_mock.call_args.kwargs["params"]
        assert params == {"limit": 10, "offset": 20}


class TestGetAgent:
    @pytest.mark.asyncio
    async def test_get_agent_builds_correct_url(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "data": {"id": "agent-uuid", "name": "my-agent", "status": "active"},
            "meta": {"is_root": True, "is_active": True},
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.get_agent("agent-uuid", auth="tok")

        url = http_mock.call_args.args[1]
        assert "/api/v1/agents/agent-uuid" in url

    @pytest.mark.asyncio
    async def test_get_agent_unwraps_data_envelope(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {
            "data": {"id": "agent-uuid", "name": "my-agent"},
            "meta": {"is_root": True, "is_active": True},
        }
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.get_agent("agent-uuid", auth="tok")

        assert result["id"] == "agent-uuid"
        assert result["name"] == "my-agent"
        assert result["is_root"] is True
        assert result["is_active"] is True
        assert "data" not in result
        assert "meta" not in result


class TestCreateDelegation:
    @pytest.mark.asyncio
    async def test_create_delegation_sends_required_fields(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"id": "del-uuid"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.create_delegation(
                delegate_agent_id="delegate-uuid",
                scopes=["api.read"],
                auth="tok",
            )

        assert result["id"] == "del-uuid"
        body = http_mock.call_args.kwargs["json"]
        assert body["delegate_agent_id"] == "delegate-uuid"
        assert body["scopes"] == ["api.read"]
        assert body["max_chain_depth"] == 3

    @pytest.mark.asyncio
    async def test_create_delegation_with_expiry(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.create_delegation(
                delegate_agent_id="delegate-uuid",
                scopes=["api.read"],
                auth="tok",
                expires_in_hours=24,
            )

        body = http_mock.call_args.kwargs["json"]
        assert "expires_at" in body

    @pytest.mark.asyncio
    async def test_create_delegation_no_expiry_omits_expires_at(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            await client.create_delegation(
                delegate_agent_id="delegate-uuid",
                scopes=["api.read"],
                auth="tok",
            )

        body = http_mock.call_args.kwargs["json"]
        assert "expires_at" not in body


class TestCheckPermission:
    @pytest.mark.asyncio
    async def test_check_permission_sends_correct_body(
        self, client: AgentAuthHTTPClient, mock_response: MagicMock
    ) -> None:
        mock_response.json.return_value = {"allowed": True, "effect": "allow"}
        http_mock = AsyncMock(return_value=mock_response)

        with patch.object(client._http, "request", new=http_mock):
            result = await client.check_permission(
                agent_id="agent-uuid",
                action="read",
                resource="/api/v1/credentials",
                auth="tok",
            )

        assert result["allowed"] is True
        body = http_mock.call_args.kwargs["json"]
        assert body == {
            "agent_id": "agent-uuid",
            "action": "read",
            "resource": "/api/v1/credentials",
        }
