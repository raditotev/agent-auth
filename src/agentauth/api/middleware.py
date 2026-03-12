"""FastAPI middleware for authentication and authorization."""

import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from agentauth.core.database import get_session_maker
from agentauth.models.agent import Agent
from agentauth.services.credential import CredentialService

# Mapping of HTTP methods to authorization actions
_METHOD_TO_ACTION = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "write",
    "PUT": "write",
    "PATCH": "write",
    "DELETE": "delete",
}

logger = structlog.get_logger()

# Paths that use stricter token-endpoint rate limits
_TOKEN_PATHS = {"/api/v1/auth/token", "/api/v1/auth/token/introspect", "/api/v1/auth/token/revoke"}

# Paths that require no authentication or authorization.
# Shared by both AuthenticationMiddleware and AuthorizationMiddleware to keep
# the two lists in sync.
_EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/ready",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/agents/bootstrap",  # Root agent self-registration
        "/api/v1/agents/quickstart",  # Compound register+credential+token shortcut
        "/api/v1/auth/jwks",  # Public JWKS for token verification
        "/api/v1/auth/token",  # Token exchange — clients authenticate here
        "/api/v1/auth/token/introspect",  # RFC 7662
        "/api/v1/auth/token/revoke",  # RFC 7009
        "/.well-known/agent-configuration",  # Discovery endpoint
        # Admin endpoints use X-Admin-Key (platform operators only), not agent auth
        "/api/v1/stats",
        "/api/v1/audit/events",
    }
)

# Path prefixes that are always exempt (e.g. interactive docs sub-paths)
_EXEMPT_PREFIXES: tuple[str, ...] = ("/docs", "/redoc", "/openapi", "/mcp")


def _is_exempt_path(path: str) -> bool:
    """Return True if the path requires no authentication or authorization."""
    if path in _EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


class RequestLoggingMiddleware:
    """Pure ASGI middleware for request/response logging with request_id propagation.

    - Skips /health and /ready endpoints entirely.
    - Generates or propagates X-Request-ID and binds it to structlog context.
    - Logs each request after response with method, path, status_code, duration_ms,
      client_ip, request_id, user_agent, and agent_id (when authenticated).
    - Applies log-level rules: 5xx→ERROR, 404-unregistered→DEBUG,
      404-registered→WARNING, other 4xx→WARNING, 2xx/3xx→INFO.
    """

    _SKIP_PATHS: frozenset[str] = frozenset({"/health", "/ready"})

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = request.url.path

        if path in self._SKIP_PATHS:
            await self.app(scope, receive, send)
            return

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        start_time = time.monotonic()
        status_code = 500

        async def send_wrapper(message: Any) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers.append("X-Request-ID", request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            agent_id = getattr(request.state, "agent_id", None)

            log_level = _request_log_level(status_code, scope)

            log_fields: dict[str, Any] = {
                "method": request.method,
                "path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_ip": request.client.host if request.client else None,
                "request_id": request_id,
                "user_agent": request.headers.get("user-agent"),
            }
            if agent_id is not None:
                log_fields["agent_id"] = str(agent_id)

            getattr(logger, log_level)("http_request", **log_fields)
            structlog.contextvars.clear_contextvars()


def _request_log_level(status_code: int, scope: Scope) -> str:
    """Determine the structlog level for a completed HTTP request."""
    if status_code >= 500:
        return "error"
    if status_code == 404:
        # If an endpoint was matched, the handler itself returned 404
        # (resource not found) → WARNING.  If no endpoint matched at all
        # the path is unregistered noise → DEBUG.
        return "warning" if scope.get("endpoint") is not None else "debug"
    if status_code >= 400:
        return "warning"
    return "info"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding window rate limiting middleware.

    - Token endpoints: 30 req/min per agent (or IP for unauthenticated)
    - Management API: 300 req/min per agent

    Adds X-RateLimit-* headers to all responses.
    Returns 429 with Retry-After when limit is exceeded.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        from agentauth.core.rate_limit import check_rate_limit

        # Choose identifier: authenticated agent ID or fallback to client IP
        agent = getattr(request.state, "agent", None)
        identifier = (
            f"agent:{agent.id}"
            if agent
            else f"ip:{request.client.host if request.client else 'unknown'}"
        )

        endpoint_type = "token" if request.url.path in _TOKEN_PATHS else "api"

        allowed, rl_headers = await check_rate_limit(identifier, endpoint_type)

        if not allowed:
            response: Response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "type": "https://agentauth.dev/problems/rate-limit-exceeded",
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": "Rate limit exceeded. Please retry after the indicated period.",
                    "instance": request.url.path,
                },
                headers={"Content-Type": "application/problem+json"},
            )
            for k, v in rl_headers.items():
                response.headers[k] = v
            return response

        response = await call_next(request)
        for k, v in rl_headers.items():
            response.headers[k] = v
        return response


class AuthorizationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that enforces authorization policies on every authenticated request.

    Runs AFTER AuthenticationMiddleware. If no agent is in request state
    (i.e. the path is exempt from auth), authorization is also skipped.

    Adds X-Authorization-Decision header to all responses for debugging.

    Note: Root agents (trust_level=ROOT) are trust anchors and bypass policy
    enforcement by design. Policy DENY rules do NOT apply to root agents.
    Use root agent credentials only for administrative operations.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Evaluate authorization policy for the current request."""
        if _is_exempt_path(request.url.path):
            return await call_next(request)

        agent = getattr(request.state, "agent", None)
        if agent is None:
            # Authentication already rejected this request; let it through to
            # surface the 401 from AuthenticationMiddleware.
            return await call_next(request)

        # Root agents are trust anchors — they bypass policy enforcement.
        # IMPORTANT: Policy deny rules cannot override root agent access.
        #
        # is_root() requires BOTH parent_agent_id is None AND trust_level == ROOT,
        # providing defense-in-depth: an agent whose trust_level was somehow set
        # to ROOT without being a true root (no parent) still goes through normal
        # policy evaluation.
        if agent.is_root():
            logger.info(
                "root_agent_policy_bypass",
                agent_id=str(agent.id),
                action=_METHOD_TO_ACTION.get(request.method.upper(), "write"),
                resource=request.url.path,
            )
            response = await call_next(request)
            response.headers["X-Authorization-Decision"] = "allow"
            return response

        action = _METHOD_TO_ACTION.get(request.method.upper(), "write")
        resource = request.url.path

        session_maker = get_session_maker()
        async with session_maker() as session:
            from agentauth.services.authorization import AuthorizationService

            auth_service = AuthorizationService(session)
            result = await auth_service.evaluate(
                agent_id=agent.id,
                action=action,
                resource=resource,
                context={"ip": request.client.host if request.client else None},
            )

        decision = "allow" if result.allowed else "deny"

        logger.info(
            "authorization_decision",
            agent_id=str(agent.id),
            action=action,
            resource=resource,
            decision=decision,
            reason=result.reason,
        )

        if not result.allowed:
            response = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "type": "https://agentauth.dev/problems/access-denied",
                    "title": "Access Denied",
                    "status": 403,
                    "detail": result.reason,
                    "instance": resource,
                    "policy_id": str(result.matching_policy_id)
                    if result.matching_policy_id
                    else None,
                    "policy_name": result.matching_policy_name,
                },
                headers={"Content-Type": "application/problem+json"},
            )
            response.headers["X-Authorization-Decision"] = decision
            return response

        response = await call_next(request)
        response.headers["X-Authorization-Decision"] = decision
        return response


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to authenticate requests via X-Agent-Key header or Bearer JWT.

    Extracts API key or Bearer token, verifies it, resolves the associated agent,
    and injects agent into request state. Returns RFC 7807 Problem
    Details on authentication failure.

    Exempt paths are defined by the module-level _EXEMPT_PATHS constant,
    shared with AuthorizationMiddleware to keep them in sync.
    """

    def __init__(
        self,
        app: ASGIApp,
        session_maker: async_sessionmaker[AsyncSession] | None = None,
    ):
        """
        Initialize authentication middleware.

        Args:
            app: FastAPI application
            session_maker: Optional session maker for testing
        """
        super().__init__(app)
        self._session_maker = session_maker

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process request and authenticate if needed."""
        # Skip authentication for exempt paths
        if _is_exempt_path(request.url.path):
            return await call_next(request)

        # Accept either X-Agent-Key (API key) or Authorization: Bearer (access token)
        api_key = request.headers.get("X-Agent-Key")
        bearer_token: str | None = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[len("Bearer ") :]

        if not api_key and not bearer_token:
            logger.warning(
                "authentication_failed",
                reason="missing_credentials",
                path=request.url.path,
                method=request.method,
            )
            return self._authentication_error_response(
                title="Missing Authentication",
                detail="Provide either X-Agent-Key header (API key) or Authorization: Bearer <token>",
                instance=request.url.path,
            )

        # Verify credentials and load agent
        try:
            if api_key:
                agent = await self._verify_api_key(api_key)
            else:
                agent = await self._verify_bearer_token(bearer_token)  # type: ignore[arg-type]

            if not agent:
                logger.warning(
                    "authentication_failed",
                    reason="invalid_api_key",
                    path=request.url.path,
                    method=request.method,
                )
                return self._authentication_error_response(
                    title="Invalid Authentication",
                    detail="The provided API key is invalid, expired, or revoked",
                    instance=request.url.path,
                )

            # Check if agent is active
            if not agent.is_active():
                logger.warning(
                    "authentication_failed",
                    reason="agent_inactive",
                    agent_id=str(agent.id),
                    status=agent.status.value,
                    path=request.url.path,
                )
                return self._authentication_error_response(
                    title="Agent Inactive",
                    detail=f"Agent is {agent.status.value} and cannot authenticate",
                    instance=request.url.path,
                )

            # Inject authenticated agent into request state
            request.state.agent = agent
            request.state.agent_id = agent.id
            request.state.trust_level = agent.trust_level

            logger.info(
                "authentication_success",
                agent_id=str(agent.id),
                agent_name=agent.name,
                trust_level=agent.trust_level.value,
                path=request.url.path,
                method=request.method,
            )

        except Exception as e:
            logger.error(
                "authentication_error",
                error=str(e),
                path=request.url.path,
                method=request.method,
            )
            return self._authentication_error_response(
                title="Authentication Error",
                detail="An error occurred during authentication",
                instance=request.url.path,
            )

        # Continue with request
        response = await call_next(request)
        return response

    async def _verify_api_key(self, api_key: str) -> Agent | None:
        """
        Verify API key and return associated agent.

        Args:
            api_key: Raw API key from header

        Returns:
            Agent if valid, None otherwise
        """
        # Create a new database session for this request
        # Use injected session maker for testing, or get the default one
        session_maker = self._session_maker or get_session_maker()
        async with session_maker() as session:
            credential_service = CredentialService(session)

            # Verify credential and update last_used_at
            credential = await credential_service.verify_credential(api_key)

            if not credential:
                return None

            # Commit the last_used_at update
            await session.commit()

            # Load the associated agent with a fresh query to ensure
            # we get the current state
            await session.refresh(credential, ["agent"])

            return credential.agent

    async def _verify_bearer_token(self, token: str) -> Agent | None:
        """
        Validate a Bearer JWT and return the associated agent.

        Args:
            token: Raw Bearer token string

        Returns:
            Agent if token is valid and agent is found, None otherwise
        """
        from sqlalchemy import select

        from agentauth.services.token import TokenService

        session_maker = self._session_maker or get_session_maker()
        async with session_maker() as session:
            token_service = TokenService(session)
            result = await token_service.validate_token(token, expected_token_type="access")

            if not result.valid or result.claims is None:
                return None

            # Load agent by sub claim (agent UUID)
            from uuid import UUID as _UUID

            try:
                agent_id = _UUID(result.claims.sub)
            except ValueError:
                return None

            agent_result = await session.execute(select(Agent).where(Agent.id == agent_id))
            return agent_result.scalar_one_or_none()

    def _authentication_error_response(
        self,
        title: str,
        detail: str,
        instance: str,
        additional_fields: dict[str, Any] | None = None,
    ) -> JSONResponse:
        """
        Create RFC 7807 Problem Details response for authentication errors.

        Args:
            title: Short summary of the problem
            detail: Detailed explanation
            instance: URI reference identifying the specific occurrence
            additional_fields: Optional additional fields

        Returns:
            JSONResponse with RFC 7807 format
        """
        problem_detail = {
            "type": "https://agentauth.dev/problems/authentication-failed",
            "title": title,
            "status": status.HTTP_401_UNAUTHORIZED,
            "detail": detail,
            "instance": instance,
        }

        if additional_fields:
            problem_detail.update(additional_fields)

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=problem_detail,
            headers={
                "Content-Type": "application/problem+json",
                "WWW-Authenticate": 'ApiKey realm="AgentAuth"',
            },
        )
