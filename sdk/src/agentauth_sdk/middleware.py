"""FastAPI middleware for validating AgentAuth tokens on incoming requests."""

from typing import Any, Awaitable, Callable

import httpx
import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = structlog.get_logger()


class AgentAuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware that validates Bearer tokens issued by AgentAuth.

    Validates the token via the AgentAuth introspection endpoint and injects
    agent identity into `request.state.agent_identity`.

    Usage::

        app.add_middleware(
            AgentAuthMiddleware,
            agentauth_base_url="https://agentauth.example.com",
            required_scopes=["api.read"],
        )
    """

    def __init__(
        self,
        app: Any,
        agentauth_base_url: str,
        required_scopes: list[str] | None = None,
        exempt_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.agentauth_base_url = agentauth_base_url.rstrip("/")
        self.required_scopes = required_scopes or []
        self.exempt_paths = exempt_paths or {"/health", "/ready", "/docs", "/openapi.json"}
        self._http = httpx.AsyncClient(timeout=5.0)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._error(401, "Missing or invalid Authorization header")

        token = auth_header[len("Bearer "):]

        try:
            introspection = await self._introspect(token)
        except Exception as e:
            logger.error("Token introspection failed", error=str(e))
            return self._error(500, "Failed to validate token")

        if not introspection.get("active"):
            return self._error(401, "Token is inactive or expired")

        # Scope enforcement
        if self.required_scopes:
            token_scopes = set((introspection.get("scope") or "").split())
            missing = set(self.required_scopes) - token_scopes
            if missing:
                return self._error(403, f"Missing required scopes: {missing}")

        # Inject agent identity into request state
        request.state.agent_identity = introspection
        return await call_next(request)

    async def _introspect(self, token: str) -> dict[str, Any]:
        resp = await self._http.post(
            f"{self.agentauth_base_url}/api/v1/auth/token/introspect",
            data={"token": token},
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _error(status_code: int, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content={"error": message},
        )
