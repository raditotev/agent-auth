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
        scopes: list[str],
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.scopes = scopes

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Return True if the token will expire within `buffer_seconds`."""
        return time.time() >= (self.expires_at - buffer_seconds)


class AgentAuthClient:
    """
    HTTP client for the AgentAuth service.

    Usage::

        client = AgentAuthClient(
            base_url="https://agentauth.example.com",
            api_key="agentauth_abc123...",
        )
        token = await client.get_token(scopes=["api.read"])
        print(token.access_token)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
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

    async def authenticate(self, scopes: list[str] | None = None) -> TokenInfo:
        """Authenticate using the configured API key and obtain a token pair."""
        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_secret": self.api_key,
        }
        if scopes:
            data["scope"] = " ".join(scopes)

        response = await self._post_with_retry("/api/v1/auth/token", form_data=data)
        token_info = self._parse_token_response(response)
        self._current_token = token_info
        logger.info("Authenticated successfully", scopes=scopes)
        return token_info

    async def get_token(self, scopes: list[str] | None = None) -> TokenInfo:
        """
        Return a valid access token, refreshing automatically if needed.

        Acquires a lock to prevent concurrent refresh races.
        """
        async with self._lock:
            if self._current_token is None or self._current_token.is_expired(
                self.refresh_buffer_seconds
            ):
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

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._current_token.refresh_token,
        }
        response = await self._post_with_retry("/api/v1/auth/token", form_data=data)
        token_info = self._parse_token_response(response)
        logger.info("Token refreshed successfully")
        return token_info

    async def introspect(self, token: str) -> dict[str, Any]:
        """Introspect a token (RFC 7662)."""
        response = await self._post_with_retry(
            "/api/v1/auth/token/introspect",
            form_data={"token": token},
        )
        return response

    async def _post_with_retry(
        self, path: str, form_data: dict[str, str]
    ) -> dict[str, Any]:
        """POST with exponential backoff retry on transient errors."""
        url = f"{self.base_url}{path}"
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                resp = await self._http.post(url, data=form_data)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 1))
                    await asyncio.sleep(retry_after)
                    continue
                resp.raise_for_status()
                return resp.json()
            except (httpx.TransportError, httpx.TimeoutException) as e:
                last_error = e
                wait = 2 ** attempt
                logger.warning("Request failed, retrying", attempt=attempt + 1, wait=wait, error=str(e))
                await asyncio.sleep(wait)
            except httpx.HTTPStatusError as e:
                raise RuntimeError(
                    f"AgentAuth API error {e.response.status_code}: {e.response.text}"
                ) from e

        raise RuntimeError(f"Request failed after {self.max_retries} retries") from last_error

    @staticmethod
    def _parse_token_response(data: dict[str, Any]) -> TokenInfo:
        access_token = data["access_token"]
        refresh_token = data.get("refresh_token")
        expires_in = data.get("expires_in", 900)
        scopes_str = data.get("scope", "")
        scopes = scopes_str.split() if scopes_str else []
        expires_at = time.time() + expires_in
        return TokenInfo(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=expires_at,
            scopes=scopes,
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> "AgentAuthClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
