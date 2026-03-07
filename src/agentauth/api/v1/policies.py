"""Policy CRUD endpoints."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
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


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
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

    # created_by_agent_id placeholder — in production this comes from the authenticated agent
    # For now accept it from the request subjects field or use a sentinel value
    # TODO: replace with authenticated agent ID once auth middleware is integrated
    from uuid import uuid4
    actor_id = uuid4()  # Will be replaced with real agent identity in Task 3.4

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
    logger.info("Policy deleted", policy_id=str(policy_id))


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
