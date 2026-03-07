"""Policy CRUD endpoints."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.models.policy import Policy
from agentauth.schemas.policy import (
    PolicyCreate,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdate,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/policies", tags=["Policies"])


async def _invalidate_policy_cache() -> None:
    """Clear all cached authorization decisions after a policy change."""
    try:
        from agentauth.core.redis import get_redis_client
        redis_client = get_redis_client()
        await redis_client.delete_pattern("authz:*")
    except Exception as e:
        logger.warning("Failed to invalidate policy cache", error=str(e))


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
) -> PolicyResponse:
    """Create a new authorization policy."""
    # Validate: deny policies need at least subjects or resources defined
    if payload.effect.value == "deny" and not payload.subjects and not payload.resources:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_policy",
                "error_description": "Deny policies must specify subjects or resources",
            },
        )

    actor_id = getattr(request.state, "agent_id", None)
    if actor_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "unauthorized",
                "error_description": "Authentication required to create policies",
            },
        )

    policy = Policy(
        created_by_agent_id=actor_id,
        name=payload.name,
        description=payload.description,
        effect=payload.effect,
        subjects=payload.subjects,
        resources=payload.resources,
        actions=payload.actions,
        conditions=payload.conditions,
        priority=payload.priority,
        enabled=payload.enabled,
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    await _invalidate_policy_cache()
    logger.info("Policy created", policy_id=str(policy.id), name=policy.name)
    return PolicyResponse.model_validate(policy)


@router.get("", response_model=PolicyListResponse)
async def list_policies(
    session: Annotated[AsyncSession, Depends(get_session)],
    enabled_only: bool = False,
) -> PolicyListResponse:
    """List all policies."""
    query = select(Policy).order_by(Policy.priority.desc(), Policy.created_at.desc())
    if enabled_only:
        query = query.where(Policy.enabled.is_(True))
    result = await session.execute(query)
    policies = list(result.scalars().all())
    return PolicyListResponse(
        data=[PolicyResponse.model_validate(p) for p in policies],
        total=len(policies),
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyResponse:
    """Get a policy by ID."""
    result = await session.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Policy not found"},
        )
    return PolicyResponse.model_validate(policy)


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    payload: PolicyUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyResponse:
    """Update an existing policy."""
    result = await session.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Policy not found"},
        )

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(policy, field, value)

    await session.commit()
    await session.refresh(policy)
    await _invalidate_policy_cache()
    logger.info("Policy updated", policy_id=str(policy.id))
    return PolicyResponse.model_validate(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a policy."""
    result = await session.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Policy not found"},
        )
    await session.delete(policy)
    await session.commit()
    await _invalidate_policy_cache()
    logger.info("Policy deleted", policy_id=str(policy_id))


@router.get(
    "/syntax",
    summary="Policy syntax reference",
    description="Returns documentation on the pattern syntax for policy subjects, resources, and conditions.",
)
async def policy_syntax() -> dict:
    """
    Policy syntax reference for programmatic clients.

    Describes the JSON structure accepted by `subjects`, `resources`, and `conditions`
    fields when creating or updating policies.
    """
    return {
        "subjects": {
            "description": "Specifies which agents the policy applies to.",
            "fields": {
                "agent_ids": {
                    "type": "array[uuid]",
                    "description": "Exact agent UUIDs to match.",
                    "example": {"agent_ids": ["550e8400-e29b-41d4-a716-446655440000"]},
                },
                "agent_types": {
                    "type": "array[string]",
                    "values": ["orchestrator", "autonomous", "assistant", "tool"],
                    "description": "Match agents by type.",
                    "example": {"agent_types": ["autonomous", "tool"]},
                },
                "trust_levels": {
                    "type": "array[string]",
                    "values": ["root", "delegated", "ephemeral"],
                    "description": "Match agents by trust level.",
                    "example": {"trust_levels": ["delegated"]},
                },
                "wildcard": {
                    "type": "boolean",
                    "description": "If true, matches all agents.",
                    "example": {"wildcard": True},
                },
            },
            "combining": "All provided fields are ANDed. An empty {} matches nothing.",
        },
        "resources": {
            "description": "Specifies which API paths or services the policy covers.",
            "fields": {
                "paths": {
                    "type": "array[string]",
                    "description": "Exact path match or prefix match using '*' wildcard.",
                    "examples": [
                        "/api/v1/agents",
                        "/api/v1/credentials/*",
                        "/api/v1/*",
                    ],
                },
                "wildcard": {
                    "type": "boolean",
                    "description": "If true, matches all resources.",
                    "example": {"wildcard": True},
                },
            },
            "combining": "An agent request matches if ANY listed path matches (OR logic).",
        },
        "actions": {
            "description": "HTTP-method-level actions that the policy covers.",
            "values": {
                "read": "GET, HEAD, OPTIONS",
                "write": "POST, PUT, PATCH",
                "delete": "DELETE",
                "execute": "Trigger or invoke operations",
                "delegate": "Create delegations",
                "admin": "Administrative operations (implies all others)",
            },
        },
        "conditions": {
            "description": "Optional additional constraints on when the policy applies.",
            "fields": {
                "time_window": {
                    "type": "object",
                    "description": "Restrict policy to a time range (UTC ISO 8601).",
                    "example": {
                        "time_window": {
                            "not_before": "2024-01-01T00:00:00Z",
                            "not_after": "2024-12-31T23:59:59Z",
                        }
                    },
                },
                "ip_ranges": {
                    "type": "array[string]",
                    "description": "CIDR ranges from which requests are permitted.",
                    "example": {"ip_ranges": ["10.0.0.0/8", "192.168.1.0/24"]},
                },
                "rate_limit": {
                    "type": "object",
                    "description": "Per-agent rate limit override for matched requests.",
                    "example": {"rate_limit": {"requests": 100, "window_seconds": 60}},
                },
            },
            "combining": "All specified conditions must be satisfied (AND logic).",
        },
        "evaluation_order": (
            "Policies are evaluated highest-priority first (priority DESC, created_at DESC). "
            "The first matching policy's effect (allow/deny) is applied. "
            "Default: deny if no policy matches."
        ),
        "examples": {
            "allow_read_only_for_tool_agents": {
                "name": "Tool agents read-only",
                "effect": "allow",
                "subjects": {"agent_types": ["tool"]},
                "resources": {"paths": ["/api/v1/*"]},
                "actions": ["read"],
                "conditions": {},
                "priority": 10,
            },
            "deny_credentials_access_for_ephemeral": {
                "name": "Block ephemeral agents from credentials",
                "effect": "deny",
                "subjects": {"trust_levels": ["ephemeral"]},
                "resources": {"paths": ["/api/v1/credentials/*"]},
                "actions": ["read", "write", "delete"],
                "conditions": {},
                "priority": 100,
            },
        },
    }


@router.post("/evaluate", response_model=PolicyEvaluateResponse)
async def evaluate_policy(
    payload: PolicyEvaluateRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyEvaluateResponse:
    """Dry-run policy evaluation — check if an agent would be allowed to perform an action."""
    from agentauth.services.authorization import AuthorizationService

    auth_service = AuthorizationService(session)
    result = await auth_service.evaluate(
        agent_id=payload.agent_id,
        action=payload.action,
        resource=payload.resource,
        context=payload.context,
    )
    return result
