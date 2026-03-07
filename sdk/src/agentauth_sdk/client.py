"""AgentAuth client — authenticate agents and manage tokens."""

import asyncio
import time
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class TokenInfo:
    """Holds a token pair with metadata."""

    def __init__(
        self,
        access_token: str,
        refresh_token: str | None,
        expires_at: float,
        refresh_before: float | None,
        scopes: list[str],
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.refresh_before = refresh_before
        self.scopes = scopes

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Return True if the token will expire within `buffer_seconds`."""
        return time.time() >= (self.expires_at - buffer_seconds)

    def needs_refresh(self) -> bool:
        """Return True if the token has passed its refresh_before deadline."""
        if self.refresh_before is not None:
            return time.time() >= self.refresh_before
        return self.is_expired()


class QuickstartResult:
    """Result from the quickstart endpoint — everything needed to start working."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.agent = data["agent"]
        self.agent_id: str = self.agent["id"]
        self.agent_name: str = self.agent["name"]
        self.api_key: str = data["api_key"]
        self.api_key_prefix: str = data["api_key_prefix"]
        self.token = _parse_token_response(data["token"])
        self.raw = data


class AgentAuthClient:
    """
    HTTP client for the AgentAuth service.

    Usage::

        async with AgentAuthClient(
            base_url="https://agentauth.example.com",
            api_key="agentauth_abc123...",
        ) as client:
            token = await client.get_token(scopes=["api.read"])
            # use token.access_token in Authorization: Bearer headers

    Or for first-time setup::

        async with AgentAuthClient(base_url="https://agentauth.example.com") as client:
            result = await client.quickstart("my-agent", "autonomous")
            # result.api_key — save this
            # result.token.access_token — use this immediately
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        refresh_buffer_seconds: int = 60,
        max_retries: int = 3,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.refresh_buffer_seconds = refresh_buffer_seconds
        self.max_retries = max_retries
        self._http = httpx.AsyncClient(timeout=timeout)
        self._current_token: TokenInfo | None = None
        self._lock = asyncio.Lock()

    # -- quickstart --

    async def quickstart(
        self,
        name: str,
        agent_type: str,
        description: str | None = None,
    ) -> QuickstartResult:
        """
        Register a new root agent and get credentials in one call.

        Returns a QuickstartResult containing:
        - agent identity (id, name, type, trust_level)
        - api_key (save this — shown only once)
        - token (ready-to-use access token)
        """
        body: dict[str, Any] = {"name": name, "agent_type": agent_type}
        if description:
            body["description"] = description

        data = await self._request("POST", "/api/v1/agents/quickstart", json=body)
        result = QuickstartResult(data)

        # Store the API key and token for subsequent calls
        self.api_key = result.api_key
        self._current_token = result.token

        logger.info(
            "Quickstart completed",
            agent_id=result.agent_id,
            agent_name=result.agent_name,
        )
        return result

    # -- authentication --

    async def authenticate(self, scopes: list[str] | None = None) -> TokenInfo:
        """Authenticate using the configured API key and obtain a token pair."""
        if not self.api_key:
            raise RuntimeError("No API key configured — call quickstart() or pass api_key to constructor")

        body: dict[str, Any] = {
            "grant_type": "client_credentials",
            "client_secret": self.api_key,
        }
        if scopes:
            body["scope"] = " ".join(scopes)

        data = await self._request("POST", "/api/v1/auth/token", json=body)
        token_info = _parse_token_response(data)
        self._current_token = token_info
        logger.info("Authenticated successfully", scopes=scopes)
        return token_info

    async def get_token(self, scopes: list[str] | None = None) -> TokenInfo:
        """
        Return a valid access token, refreshing automatically if needed.

        Acquires a lock to prevent concurrent refresh races.
        """
        async with self._lock:
            if self._current_token is None or self._current_token.needs_refresh():
                if (
                    self._current_token is not None
                    and self._current_token.refresh_token is not None
                    and not self._current_token.is_expired(buffer_seconds=0)
                ):
                    self._current_token = await self.refresh_token()
                else:
                    self._current_token = await self.authenticate(scopes)
            return self._current_token

    async def refresh_token(self) -> TokenInfo:
        """Exchange the current refresh token for a new token pair."""
        if self._current_token is None or self._current_token.refresh_token is None:
            raise RuntimeError("No refresh token available — call authenticate() first")

        data = await self._request(
            "POST",
            "/api/v1/auth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": self._current_token.refresh_token,
            },
        )
        token_info = _parse_token_response(data)
        logger.info("Token refreshed successfully")
        return token_info

    async def introspect(self, token: str) -> dict[str, Any]:
        """Introspect a token (RFC 7662)."""
        return await self._request(
            "POST",
            "/api/v1/auth/token/introspect",
            data={"token": token},
        )

    async def revoke(self, token: str) -> None:
        """Revoke a token (RFC 7009)."""
        await self._request(
            "POST",
            "/api/v1/auth/token/revoke",
            data={"token": token},
        )

    # -- authenticated API calls --

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Make an authenticated request to the AgentAuth API.

        Automatically obtains/refreshes the access token.

        Args:
            method: HTTP method
            path: API path (e.g. "/api/v1/agents")
            json: Request body
            params: Query parameters
            scopes: Scopes needed for this request (for auto-auth)
        """
        token = await self.get_token(scopes)
        return await self._request(
            method,
            path,
            json=json,
            params=params,
            headers={"Authorization": f"Bearer {token.access_token}"},
        )

    # -- convenience methods --

    async def list_agents(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """List agents."""
        return await self.request("GET", "/api/v1/agents", params={"limit": limit, "offset": offset})

    async def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Get agent details."""
        return await self.request("GET", f"/api/v1/agents/{agent_id}")

    async def create_credential(
        self, agent_id: str, scopes: list[str] | None = None
    ) -> dict[str, Any]:
        """Create a new API key for an agent. Raw key is returned ONCE."""
        body: dict[str, Any] = {"agent_id": agent_id, "type": "api_key"}
        if scopes:
            body["scopes"] = scopes
        return await self.request("POST", "/api/v1/credentials", json=body)

    async def rotate_credential(self, credential_id: str) -> dict[str, Any]:
        """Rotate an API key. Returns new raw key ONCE."""
        return await self.request("POST", f"/api/v1/credentials/{credential_id}/rotate")

    async def create_delegation(
        self,
        delegate_agent_id: str,
        scopes: list[str],
        max_chain_depth: int = 3,
    ) -> dict[str, Any]:
        """Delegate permissions to another agent."""
        return await self.request(
            "POST",
            "/api/v1/delegations",
            json={
                "delegate_agent_id": delegate_agent_id,
                "scopes": scopes,
                "max_chain_depth": max_chain_depth,
            },
        )

    async def check_permission(
        self, agent_id: str, action: str, resource: str
    ) -> dict[str, Any]:
        """Dry-run policy evaluation."""
        return await self.request(
            "POST",
            "/api/v1/policies/evaluate",
            json={"agent_id": agent_id, "action": action, "resource": resource},
        )

    # -- internal --

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """HTTP request with exponential backoff retry on transient errors."""
        url = f"{self.base_url}{path}"
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                resp = await self._http.request(
                    method, url, json=json, data=data, headers=headers, params=params
                )
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 1))
                    await asyncio.sleep(retry_after)
                    continue
                resp.raise_for_status()
                if resp.status_code == 204:
                    return {"ok": True}
                return resp.json()
            except (httpx.TransportError, httpx.TimeoutException) as e:
                last_error = e
                wait = 2**attempt
                logger.warning("Request failed, retrying", attempt=attempt + 1, wait=wait, error=str(e))
                await asyncio.sleep(wait)
            except httpx.HTTPStatusError as e:
                raise RuntimeError(
                    f"AgentAuth API error {e.response.status_code}: {e.response.text}"
                ) from e

        raise RuntimeError(f"Request failed after {self.max_retries} retries") from last_error

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> "AgentAuthClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


def _parse_token_response(data: dict[str, Any]) -> TokenInfo:
    """Parse a token endpoint response into a TokenInfo."""
    access_token = data["access_token"]
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", 900)
    scopes_str = data.get("scope", "")
    scopes = scopes_str.split() if scopes_str else []
    expires_at = time.time() + expires_in

    # Use refresh_before from server if available, otherwise derive from buffer
    refresh_before: float | None = None
    if "refresh_before" in data:
        from datetime import datetime, timezone
        try:
            rb = datetime.fromisoformat(data["refresh_before"])
            refresh_before = rb.timestamp()
        except (ValueError, TypeError):
            pass
    if refresh_before is None:
        refresh_before = expires_at - 60

    return TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        refresh_before=refresh_before,
        scopes=scopes,
    )
