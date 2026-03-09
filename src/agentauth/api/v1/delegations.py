"""Delegation management endpoints."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select

from agentauth.core.database import DbSession
from agentauth.models.delegation import Delegation
from agentauth.schemas.delegation import (
    DelegationChainResponse,
    DelegationCreate,
    DelegationListResponse,
    DelegationResponse,
)
from agentauth.services.delegation import DelegationService
from agentauth.services.identity import IdentityService

logger = structlog.get_logger()

router = APIRouter(prefix="/delegations", tags=["Delegations"])


@router.post("", response_model=DelegationResponse, status_code=status.HTTP_201_CREATED)
async def create_delegation(
    payload: DelegationCreate,
    session: DbSession,
    request: Request,
) -> DelegationResponse:
    """Create a new delegation from the authenticated agent to a delegate."""
    agent = getattr(request.state, "agent", None)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "error_description": "Authentication required to create delegations"},
        )
    delegator_id = agent.id

    service = DelegationService(session)
    try:
        delegation = await service.create_delegation(
            delegator_agent_id=delegator_id,
            delegate_agent_id=payload.delegate_agent_id,
            scopes=payload.scopes,
            constraints=payload.constraints,
            max_chain_depth=payload.max_chain_depth,
            expires_at=payload.expires_at,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_delegation", "error_description": str(e)},
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "error_description": str(e)},
        ) from e
    return DelegationResponse.from_model(delegation)


@router.get("", response_model=DelegationListResponse)
async def list_delegations(
    request: Request,
    session: DbSession,
    active_only: bool = True,
) -> DelegationListResponse:
    """List delegations scoped to the caller's subtree.

    Root agents see all delegations system-wide.
    Non-root agents see only delegations where they are the delegator, the
    delegate, or an ancestor of either party (i.e. the delegation involves
    at least one agent in the caller's subtree).
    """
    caller = getattr(request.state, "agent", None)
    if caller is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "error_description": "Authentication required to list delegations"},
        )

    query = select(Delegation).order_by(Delegation.created_at.desc())

    if not caller.is_root():
        # Restrict to delegations involving any agent in the caller's subtree.
        identity_service = IdentityService(session)
        subtree_ids = await identity_service.get_subtree_agent_ids(caller.id)
        query = query.where(
            or_(
                Delegation.delegator_agent_id.in_(subtree_ids),
                Delegation.delegate_agent_id.in_(subtree_ids),
            )
        )

    result = await session.execute(query)
    all_delegations = list(result.scalars().all())
    if active_only:
        all_delegations = [d for d in all_delegations if d.is_active()]

    logger.debug(
        "list_delegations",
        caller_id=str(caller.id),
        is_root=caller.is_root(),
        count=len(all_delegations),
    )

    return DelegationListResponse(
        data=[DelegationResponse.from_model(d) for d in all_delegations],
        total=len(all_delegations),
    )


@router.get("/{delegation_id}/chain", response_model=DelegationChainResponse)
async def get_delegation_chain(
    delegation_id: UUID,
    session: DbSession,
) -> DelegationChainResponse:
    """Get the full delegation chain for a delegation."""
    service = DelegationService(session)
    chain = await service.get_delegation_chain(delegation_id)
    if not chain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Delegation not found"},
        )

    # Effective scopes = intersection across chain
    scope_sets = [set(d.scopes) for d in chain]
    effective: set[str] = scope_sets[0] if scope_sets else set()
    for s in scope_sets[1:]:
        effective = effective.intersection(s)

    return DelegationChainResponse(
        delegation_id=delegation_id,
        chain=[DelegationResponse.from_model(d) for d in chain],
        effective_scopes=sorted(effective),
    )


@router.delete("/{delegation_id}", status_code=status.HTTP_200_OK)
async def revoke_delegation(
    delegation_id: UUID,
    session: DbSession,
    cascade: bool = True,
) -> dict:
    """Revoke a delegation and optionally all downstream delegations."""
    service = DelegationService(session)
    count = await service.revoke_delegation(delegation_id, cascade=cascade)
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "error_description": "Delegation not found"},
        )
    return {"revoked": count}
