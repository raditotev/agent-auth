"""HTTP client for communicating with the AgentAuth service."""

from typing import Any

import httpx


class AgentAuthHTTPClient:
    """Thin async HTTP wrapper around the AgentAuth REST API."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> "AgentAuthHTTPClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

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
        """Register a new agent and return a flattened response.

        Normalizes the API envelope so token fields (access_token, refresh_token,
        token_type, expires_in, expires_at, refresh_before) sit alongside agent
        and api_key at the top level.
        """
        body: dict[str, Any] = {"name": name, "agent_type": agent_type}
        if description is not None:
            body["description"] = description
        raw = await self._request("POST", "/api/v1/agents/quickstart", json=body)
        token_obj: dict[str, Any] = raw.get("token") or {}
        return {
            "agent": raw.get("agent"),
            "api_key": raw.get("api_key"),
            "access_token": token_obj.get("access_token"),
            "refresh_token": token_obj.get("refresh_token"),
            "token_type": token_obj.get("token_type", "Bearer"),
            "expires_in": token_obj.get("expires_in"),
            "expires_at": token_obj.get("expires_at"),
            "refresh_before": token_obj.get("refresh_before"),
        }

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
        """Issue a new API key, flattening {"credential": {...}, "raw_key": "..."} to top level."""
        body: dict[str, Any] = {"agent_id": agent_id, "type": "api_key"}
        if scopes:
            body["scopes"] = scopes
        raw = await self._request(
            "POST",
            "/api/v1/credentials",
            json=body,
            headers=self._auth_headers(token=auth),
        )
        result = dict(raw.get("credential") or raw)
        if "raw_key" in raw:
            result["raw_key"] = raw["raw_key"]
        return result

    async def rotate_credential(self, credential_id: str, auth: str) -> dict[str, Any]:
        """Rotate an API key, returning the new credential flat with raw_key and old_credential_id."""
        raw = await self._request(
            "POST",
            f"/api/v1/credentials/{credential_id}/rotate",
            headers=self._auth_headers(token=auth),
        )
        new_cred: dict[str, Any] = dict(raw.get("new_credential") or raw)
        if "raw_key" in raw:
            new_cred["raw_key"] = raw["raw_key"]
        old_cred: dict[str, Any] = raw.get("old_credential") or {}
        if old_id := old_cred.get("id"):
            new_cred["old_credential_id"] = old_id
        return new_cred

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
        """Fetch agent details, unwrapping the {"data": {...}, "meta": {...}} envelope."""
        raw = await self._request(
            "GET",
            f"/api/v1/agents/{agent_id}",
            headers=self._auth_headers(token=auth),
        )
        agent = dict(raw.get("data") or raw)
        meta: dict[str, Any] = raw.get("meta") or {}
        if meta:
            agent.update(meta)
        return agent

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
