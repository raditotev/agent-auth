"""Delegation management endpoints."""

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.models.delegation import Delegation
from agentauth.schemas.delegation import (
    DelegationChainResponse,
    DelegationCreate,
    DelegationListResponse,
    DelegationResponse,
)
from agentauth.services.delegation import DelegationService

logger = structlog.get_logger()

router = APIRouter(prefix="/delegations", tags=["Delegations"])


@router.post("", response_model=DelegationResponse, status_code=status.HTTP_201_CREATED)
async def create_delegation(
    payload: DelegationCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DelegationResponse:
    """Create a new delegation from the authenticated agent to a delegate."""
    # TODO: replace with authenticated agent_id from request state (Task 3.4)
    from uuid import uuid4
    delegator_id = uuid4()  # placeholder until auth middleware injects agent

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
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "error_description": str(e)},
        )
    return DelegationResponse.from_model(delegation)


@router.get("", response_model=DelegationListResponse)
async def list_delegations(
    session: Annotated[AsyncSession, Depends(get_session)],
    active_only: bool = True,
) -> DelegationListResponse:
    """List delegations."""
    query = select(Delegation).order_by(Delegation.created_at.desc())
    result = await session.execute(query)
    all_delegations = list(result.scalars().all())
    if active_only:
        all_delegations = [d for d in all_delegations if d.is_active()]
    return DelegationListResponse(
        data=[DelegationResponse.from_model(d) for d in all_delegations],
        total=len(all_delegations),
    )


@router.get("/{delegation_id}/chain", response_model=DelegationChainResponse)
async def get_delegation_chain(
    delegation_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
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
    session: Annotated[AsyncSession, Depends(get_session)],
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
