"""Agent management API endpoints."""

import secrets
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from agentauth.config import settings
from agentauth.core.database import DbSession
from agentauth.core.rate_limit import check_rate_limit
from agentauth.models.agent import Agent, AgentStatus
from agentauth.schemas.agent import (
    AgentBootstrapCreate,
    AgentCreate,
    AgentDetailResponse,
    AgentListResponse,
    AgentQuickstartResponse,
    AgentResponse,
    AgentUpdate,
)
from agentauth.services.identity import IdentityService

logger = structlog.get_logger()

router = APIRouter(prefix="/agents", tags=["agents"])


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, honouring X-Forwarded-For when present."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _bootstrap_rate_limit(request: Request) -> None:
    """
    FastAPI dependency: enforce IP-based rate limiting on bootstrap endpoints.

    Bootstrap and quickstart bypass agent authentication, so they need their
    own stricter per-IP sliding-window limit (configurable via
    RATE_LIMIT_BOOTSTRAP_REQUESTS / rate_limit_window_seconds).

    Raises:
        HTTPException 429 with Retry-After when the limit is exceeded.
    """
    ip = _get_client_ip(request)
    identifier = f"ip:{ip}"
    allowed, rl_headers = await check_rate_limit(identifier, "bootstrap")

    if not allowed:
        logger.warning(
            "bootstrap_rate_limit_exceeded",
            ip=ip,
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "type": "https://agentauth.dev/problems/rate-limit-exceeded",
                "title": "Too Many Requests",
                "status": 429,
                "detail": (
                    "Bootstrap rate limit exceeded. "
                    "Please retry after the indicated period."
                ),
                "instance": request.url.path,
            },
            headers=rl_headers,
        )

    # Stash rate-limit headers so the route handler can forward them
    request.state.bootstrap_rl_headers = rl_headers


def _check_bootstrap_token(
    x_bootstrap_token: Annotated[str | None, Header()] = None,
) -> None:
    """
    FastAPI dependency: validate the optional bootstrap invite token.

    When BOOTSTRAP_TOKEN is configured in settings every request to
    bootstrap/quickstart must supply a matching X-Bootstrap-Token header.
    A missing or incorrect token produces 403 Forbidden.

    When BOOTSTRAP_TOKEN is unset (default) this dependency is a no-op --
    open registration is allowed (development only).
    """
    if settings.bootstrap_token is None:
        return  # Open registration -- no invite code required

    if not x_bootstrap_token or not secrets.compare_digest(
        x_bootstrap_token, settings.bootstrap_token
    ):
        logger.warning("bootstrap_token_invalid", provided=bool(x_bootstrap_token))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "type": "https://agentauth.dev/problems/bootstrap-token-required",
                "title": "Bootstrap Token Required",
                "status": 403,
                "detail": (
                    "A valid X-Bootstrap-Token header is required to register a root agent "
                    "in this environment."
                ),
                "instance": "/api/v1/agents/bootstrap",
            },
        )


def agent_to_response(agent: "Agent") -> AgentResponse:
    """Convert Agent model to AgentResponse schema, avoiding SQLAlchemy metadata."""
    return AgentResponse(
        id=agent.id,
        parent_agent_id=agent.parent_agent_id,
        name=agent.name,
        agent_type=agent.agent_type,
        description=agent.description,
        homepage_url=agent.homepage_url,
        public_key=agent.public_key,
        trust_level=agent.trust_level,
        status=agent.status,
        max_child_depth=agent.max_child_depth,
        agent_metadata=agent.agent_metadata,
        deactivated_at=agent.deactivated_at,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
    )


def get_identity_service(
    session: DbSession,
) -> IdentityService:
    """Dependency for getting identity service."""
    return IdentityService(session)


@router.post(
    "/quickstart",
    response_model=AgentQuickstartResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Quickstart: register agent + get credentials in one call",
    description=(
        "Registers a root agent, issues an API key, and returns a ready-to-use access token "
        "in a single request. Ideal for programmatic agent bootstrapping. "
        "The API key is shown **once** -- store it securely."
    ),
    dependencies=[
        Depends(_bootstrap_rate_limit),
        Depends(_check_bootstrap_token),
    ],
)
async def quickstart(
    data: AgentBootstrapCreate,
    session: DbSession,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentQuickstartResponse:
    """
    Compound bootstrap endpoint: register -> credential -> token in one round-trip.

    Equivalent to:
    1. POST /agents/bootstrap
    2. POST /credentials
    3. POST /auth/token (client_credentials)
    """
    from agentauth.models.credential import CredentialType
    from agentauth.services.credential import CredentialService
    from agentauth.services.token import TokenService

    try:
        # 1. Register root agent
        agent = await identity_service.create_root_agent(data)

        # 2. Issue an API key with all default scopes
        credential_service = CredentialService(session)
        credential, raw_key = await credential_service.create_credential(
            agent_id=agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=None,  # no restriction -- use all available
            expires_at=None,
            metadata=None,
            actor_id=agent.id,
        )

        # 3. Mint an access token
        token_service = TokenService(session)
        token_response = await token_service.mint_token(
            agent=agent,
            scopes=credential.scopes or [],
        )

        await session.commit()

        logger.info(
            "Agent quickstart completed",
            agent_id=str(agent.id),
            agent_name=agent.name,
        )

        return AgentQuickstartResponse(
            agent=agent_to_response(agent),
            api_key=raw_key,
            api_key_prefix=credential.prefix,
            token=token_response,
        )

    except ValueError as e:
        logger.warning("Quickstart failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error("Quickstart error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete agent quickstart",
        ) from e


@router.post(
    "/bootstrap",
    response_model=AgentDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bootstrap a root agent",
    description="Self-register a new root agent with minimal credentials. "
    "Root agents have no parent and serve as trust anchors for their subtree.",
    dependencies=[
        Depends(_bootstrap_rate_limit),
        Depends(_check_bootstrap_token),
    ],
)
async def bootstrap_root_agent(
    data: AgentBootstrapCreate,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """Bootstrap a root agent (self-registration)."""
    try:
        agent = await identity_service.create_root_agent(data)
        # Manually construct response to avoid SQLAlchemy metadata attribute
        return AgentDetailResponse(
            data=agent_to_response(agent),
            meta={
                "message": "Root agent created successfully",
                "is_root": True,
            },
        )
    except ValueError as e:
        logger.warning("Failed to create root agent", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error("Error creating root agent", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create root agent",
        ) from e


@router.post(
    "",
    response_model=AgentDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a child agent",
    description="Register a new child agent under an existing parent agent. "
    "The parent must be active and allow child agents.",
)
async def create_agent(
    data: AgentCreate,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """Create a new child agent."""
    try:
        agent = await identity_service.create_child_agent(data)
        return AgentDetailResponse(
            data=agent_to_response(agent),
            meta={
                "message": "Agent created successfully",
                "is_root": False,
                "parent_agent_id": str(agent.parent_agent_id),
            },
        )
    except ValueError as e:
        logger.warning("Failed to create agent", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error("Error creating agent", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create agent",
        ) from e


@router.get(
    "",
    response_model=AgentListResponse,
    summary="List agents",
    description=(
        "List agents with optional filtering by parent and status. "
        "Results are scoped to the caller's subtree -- root agents see all agents, "
        "non-root agents see only their own descendants. "
        "Supports pagination via limit and offset parameters."
    ),
)
async def list_agents(
    request: Request,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
    parent_agent_id: Annotated[UUID | None, Query(description="Filter by parent agent ID")] = None,
    status_filter: Annotated[AgentStatus | None, Query(alias="status", description="Filter by agent status")] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Maximum results to return")] = 50,
    offset: Annotated[int, Query(ge=0, description="Offset for pagination")] = 0,
) -> AgentListResponse:
    """List agents scoped to the caller's subtree."""
    try:
        caller = getattr(request.state, "agent", None)
        if caller is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        subtree_ids: list[UUID] | None = None
        if not caller.is_root():
            subtree_ids = await identity_service.get_subtree_agent_ids(caller.id)

        agents = await identity_service.list_agents(
            parent_agent_id=parent_agent_id,
            status=status_filter,
            limit=limit,
            offset=offset,
            subtree_ids=subtree_ids,
        )
        return AgentListResponse(
            data=[agent_to_response(agent) for agent in agents],
            meta={
                "total": len(agents),
                "limit": limit,
                "offset": offset,
                "parent_agent_id": str(parent_agent_id) if parent_agent_id else None,
                "status_filter": status_filter.value if status_filter else None,
            },
        )
    except Exception as e:
        logger.error("Error listing agents", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list agents",
        ) from e


@router.get(
    "/{agent_id}",
    response_model=AgentDetailResponse,
    summary="Get agent details",
    description="Retrieve detailed information about a specific agent by ID.",
)
async def get_agent(
    agent_id: UUID,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """Get agent by ID."""
    agent = await identity_service.get_agent_by_id(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return AgentDetailResponse(
        data=agent_to_response(agent),
        meta={
            "is_root": agent.is_root(),
            "is_active": agent.is_active(),
        },
    )


@router.patch(
    "/{agent_id}",
    response_model=AgentDetailResponse,
    summary="Update agent",
    description="Update agent details. Only provided fields will be updated.",
)
async def update_agent(
    agent_id: UUID,
    data: AgentUpdate,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """Update agent details."""
    try:
        agent = await identity_service.update_agent(agent_id, data)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {agent_id} not found",
            )

        return AgentDetailResponse(
            data=agent_to_response(agent),
            meta={"message": "Agent updated successfully"},
        )
    except HTTPException:
        # Re-raise HTTP exceptions (like 404)
        raise
    except ValueError as e:
        logger.warning("Failed to update agent", agent_id=str(agent_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error("Error updating agent", agent_id=str(agent_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update agent",
        ) from e


@router.delete(
    "/{agent_id}",
    response_model=AgentDetailResponse,
    summary="Deactivate agent",
    description="Deactivate an agent (soft delete). Sets status to SUSPENDED "
    "and records deactivation timestamp.",
)
async def deactivate_agent(
    agent_id: UUID,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """Deactivate an agent."""
    agent = await identity_service.deactivate_agent(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return AgentDetailResponse(
        data=agent_to_response(agent),
        meta={
            "message": "Agent deactivated successfully",
            "deactivated_at": agent.deactivated_at.isoformat() if agent.deactivated_at else None,
        },
    )


@router.get(
    "/{agent_id}/children",
    response_model=AgentListResponse,
    summary="List child agents",
    description="Get all direct children of a specific agent.",
)
async def list_agent_children(
    agent_id: UUID,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentListResponse:
    """List child agents of a specific agent."""
    # First verify parent exists
    parent = await identity_service.get_agent_by_id(agent_id)
    if not parent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    children = await identity_service.get_agent_children(agent_id)
    return AgentListResponse(
        data=[agent_to_response(child) for child in children],
        meta={
            "total": len(children),
            "parent_agent_id": str(agent_id),
            "parent_name": parent.name,
        },
    )


@router.get(
    "/{agent_id}/credentials",
    response_model=AgentDetailResponse,
    summary="List agent credentials",
    description="Get all credentials associated with a specific agent.",
)
async def list_agent_credentials(
    agent_id: UUID,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AgentDetailResponse:
    """List credentials for a specific agent."""
    agent = await identity_service.get_agent_with_credentials(agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {agent_id} not found",
        )

    return AgentDetailResponse(
        data=agent_to_response(agent),
        meta={
            "credentials_count": len(agent.credentials),
            "credentials": [
                {
                    "id": str(cred.id),
                    "type": cred.type.value,
                    "prefix": cred.prefix,
                    "created_at": cred.created_at.isoformat(),
                    "is_valid": cred.is_valid(),
                }
                for cred in agent.credentials
            ],
        },
    )
