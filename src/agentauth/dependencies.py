"""FastAPI dependency injection utilities."""

import secrets
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status

from agentauth.config import settings
from agentauth.models.agent import Agent, TrustLevel


@dataclass
class AgentIdentity:
    """Validated agent identity extracted from a Bearer JWT."""

    sub: str
    agent_type: str
    trust_level: str
    scopes: list[str] = field(default_factory=list)
    parent_agent_id: str | None = None
    delegation_chain: list[str] | None = None
    jti: str | None = None
    raw_claims: dict[str, Any] = field(default_factory=dict)


async def verify_agent(request: Request) -> AgentIdentity:
    """
    FastAPI dependency that extracts and validates a Bearer JWT.

    Fetches the JWKS from the local token service (cached in Redis),
    validates the token signature and claims, checks token is not revoked,
    and injects an AgentIdentity into the request.

    Raises:
        HTTPException 401: If the token is missing, invalid, or expired.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://agentauth.dev/problems/authentication-required",
                "title": "Authentication Required",
                "status": 401,
                "detail": "Bearer token required in Authorization header",
            },
            headers={"WWW-Authenticate": 'Bearer realm="AgentAuth"'},
        )

    token = auth_header[len("Bearer "):]

    # Use the token service to validate (already handles JWKS + revocation check)
    from agentauth.core.database import get_session_maker
    from agentauth.services.token import TokenService

    session_maker = get_session_maker()
    async with session_maker() as session:
        token_service = TokenService(session)
        result = await token_service.validate_token(token, expected_token_type="access")

    if not result.valid or result.claims is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://agentauth.dev/problems/invalid-token",
                "title": "Invalid Token",
                "status": 401,
                "detail": result.error or "Token validation failed",
            },
            headers={"WWW-Authenticate": 'Bearer realm="AgentAuth"'},
        )

    claims = result.claims
    identity = AgentIdentity(
        sub=claims.sub,
        agent_type=claims.agent_type.value,
        trust_level=claims.trust_level.value,
        scopes=claims.scopes,
        parent_agent_id=str(claims.parent_agent_id) if claims.parent_agent_id else None,
        delegation_chain=[str(uid) for uid in claims.delegation_chain] if claims.delegation_chain else None,
        jti=claims.jti,
        raw_claims=claims.model_dump(mode="json"),
    )

    # Inject into request state for downstream access
    request.state.agent_identity = identity
    return identity


def requires_scope(*scopes: str):
    """
    Dependency factory that enforces one or more required scopes.

    Usage::

        @router.get("/files")
        async def list_files(
            identity: Annotated[AgentIdentity, Depends(requires_scope("files.read"))]
        ):
            ...
    """

    async def check_scopes(
        identity: Annotated[AgentIdentity, Depends(verify_agent)],
    ) -> AgentIdentity:
        token_scopes = set(identity.scopes)
        missing = set(scopes) - token_scopes
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "type": "https://agentauth.dev/problems/insufficient-scope",
                    "title": "Insufficient Scope",
                    "status": 403,
                    "detail": f"Missing required scopes: {sorted(missing)}",
                    "required_scopes": sorted(scopes),
                    "token_scopes": sorted(token_scopes),
                },
            )
        return identity

    return check_scopes


def get_current_agent(request: Request) -> Agent:
    """
    FastAPI dependency to get the current authenticated agent.

    This dependency extracts the agent from the request state,
    which is injected by the AuthenticationMiddleware.

    Args:
        request: FastAPI request object

    Returns:
        Authenticated Agent object

    Raises:
        HTTPException: 401 if agent is not authenticated

    Example:
        ```python
        @router.get("/protected")
        async def protected_endpoint(
            agent: Annotated[Agent, Depends(get_current_agent)]
        ):
            return {"agent_id": agent.id, "name": agent.name}
        ```
    """
    if not hasattr(request.state, "agent"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://agentauth.dev/problems/authentication-required",
                "title": "Authentication Required",
                "status": status.HTTP_401_UNAUTHORIZED,
                "detail": "This endpoint requires authentication. Please provide a valid X-Agent-Key header.",
            },
            headers={"WWW-Authenticate": 'ApiKey realm="AgentAuth"'},
        )

    return request.state.agent


def require_admin_key(request: Request) -> None:
    """
    FastAPI dependency for platform admin endpoints (stats, audit).

    Requires X-Admin-Key header to match ADMIN_API_KEY. Used by project
    maintainers/operators — not agent authentication. Root agents cannot
    access admin endpoints; only the configured admin key can.

    Raises:
        HTTPException 401: If admin key is not configured or header is missing/invalid.
    """
    if not settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "type": "https://agentauth.dev/problems/admin-not-configured",
                "title": "Admin Not Configured",
                "status": 503,
                "detail": "Admin endpoints require ADMIN_API_KEY to be set. "
                "Contact the platform operator.",
            },
        )

    key = request.headers.get("X-Admin-Key")
    if not key or not secrets.compare_digest(key, settings.admin_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://agentauth.dev/problems/admin-authentication-failed",
                "title": "Admin Authentication Required",
                "status": 401,
                "detail": "Provide a valid X-Admin-Key header for platform admin access.",
            },
            headers={"WWW-Authenticate": 'AdminKey realm="AgentAuth"'},
        )


def require_root_agent(
    agent: Annotated[Agent, Depends(get_current_agent)],
) -> Agent:
    """
    FastAPI dependency to require a root agent.

    Args:
        agent: Current authenticated agent

    Returns:
        Agent if it's a root agent

    Raises:
        HTTPException: 403 if agent is not a root agent

    Example:
        ```python
        @router.post("/admin/operation")
        async def admin_operation(
            agent: Annotated[Agent, Depends(require_root_agent)]
        ):
            return {"message": "Root agent only operation"}
        ```
    """
    if not agent.is_root():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://agentauth.dev/problems/insufficient-privileges",
                "title": "Insufficient Privileges",
                "status": status.HTTP_403_FORBIDDEN,
                "detail": "This operation requires a root agent",
                "required_trust_level": TrustLevel.ROOT.value,
                "current_trust_level": agent.trust_level.value,
            },
        )

    return agent


def require_trust_level(minimum_level: TrustLevel):
    """
    Factory function to create a dependency that requires a minimum trust level.

    Args:
        minimum_level: Minimum required trust level

    Returns:
        Dependency function

    Example:
        ```python
        @router.post("/sensitive-operation")
        async def sensitive_operation(
            agent: Annotated[Agent, Depends(require_trust_level(TrustLevel.DELEGATED))]
        ):
            return {"message": "Operation allowed"}
        ```
    """

    def check_trust_level(
        agent: Annotated[Agent, Depends(get_current_agent)],
    ) -> Agent:
        """Check if agent meets minimum trust level requirement."""
        # Trust level hierarchy: ROOT > DELEGATED > EPHEMERAL
        trust_hierarchy = {
            TrustLevel.ROOT: 3,
            TrustLevel.DELEGATED: 2,
            TrustLevel.EPHEMERAL: 1,
        }

        if trust_hierarchy.get(agent.trust_level, 0) < trust_hierarchy.get(
            minimum_level, 0
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "type": "https://agentauth.dev/problems/insufficient-trust-level",
                    "title": "Insufficient Trust Level",
                    "status": status.HTTP_403_FORBIDDEN,
                    "detail": f"This operation requires at least {minimum_level.value} trust level",
                    "required_trust_level": minimum_level.value,
                    "current_trust_level": agent.trust_level.value,
                },
            )

        return agent

    return check_trust_level


# Type alias for commonly used dependency
CurrentAgent = Annotated[Agent, Depends(get_current_agent)]
RootAgent = Annotated[Agent, Depends(require_root_agent)]
