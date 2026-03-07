"""HTTP client for communicating with the AgentAuth service."""

from typing import Any

import httpx


class AgentAuthHTTPClient:
    """Thin async HTTP wrapper around the AgentAuth REST API."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(timeout=timeout)

    # -- helpers --

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = await self._http.request(
            method, url, json=json, data=data, headers=headers, params=params
        )
        resp.raise_for_status()
        if resp.status_code == 204:
            return {"ok": True}
        return resp.json()

    def _auth_headers(self, api_key: str | None = None, token: str | None = None) -> dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        if api_key:
            return {"X-Agent-Key": api_key}
        return {}

    # -- public API methods --

    async def quickstart(
        self,
        name: str,
        agent_type: str,
        description: str | None = None,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/agents/quickstart",
            json={
                "name": name,
                "agent_type": agent_type,
                "description": description,
            },
        )

    async def authenticate(
        self,
        api_key: str,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "grant_type": "client_credentials",
            "client_secret": api_key,
        }
        if scopes:
            body["scope"] = " ".join(scopes)
        return await self._request("POST", "/api/v1/auth/token", json=body)

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/auth/token",
            json={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )

    async def introspect_token(self, token: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/auth/token/introspect",
            data={"token": token},
        )

    async def revoke_token(self, token: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/auth/token/revoke",
            data={"token": token},
        )

    async def create_credential(
        self,
        agent_id: str,
        auth: str,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"agent_id": agent_id, "type": "api_key"}
        if scopes:
            body["scopes"] = scopes
        return await self._request(
            "POST",
            "/api/v1/credentials",
            json=body,
            headers=self._auth_headers(token=auth),
        )

    async def rotate_credential(self, credential_id: str, auth: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/api/v1/credentials/{credential_id}/rotate",
            headers=self._auth_headers(token=auth),
        )

    async def revoke_credential(self, credential_id: str, auth: str) -> dict[str, Any]:
        return await self._request(
            "DELETE",
            f"/api/v1/credentials/{credential_id}",
            headers=self._auth_headers(token=auth),
        )

    async def list_agents(
        self, auth: str, limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            "/api/v1/agents",
            headers=self._auth_headers(token=auth),
            params={"limit": limit, "offset": offset},
        )

    async def get_agent(self, agent_id: str, auth: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/api/v1/agents/{agent_id}",
            headers=self._auth_headers(token=auth),
        )

    async def create_delegation(
        self,
        delegate_agent_id: str,
        scopes: list[str],
        auth: str,
        max_chain_depth: int = 3,
        expires_in_hours: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "delegate_agent_id": delegate_agent_id,
            "scopes": scopes,
            "max_chain_depth": max_chain_depth,
        }
        if expires_in_hours is not None:
            from datetime import datetime, timedelta, timezone
            body["expires_at"] = (
                datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            ).isoformat()
        return await self._request(
            "POST",
            "/api/v1/delegations",
            json=body,
            headers=self._auth_headers(token=auth),
        )

    async def check_permission(
        self,
        agent_id: str,
        action: str,
        resource: str,
        auth: str,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/api/v1/policies/evaluate",
            json={
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
            },
            headers=self._auth_headers(token=auth),
        )

    async def discover(self) -> dict[str, Any]:
        return await self._request("GET", "/.well-known/agent-configuration")

    async def close(self) -> None:
        await self._http.aclose()
