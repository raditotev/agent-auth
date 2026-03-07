"""Scope registry CRUD endpoints."""

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.schemas.scope import ScopeCreate, ScopeListResponse, ScopeResponse, ScopeResolveResponse
from agentauth.services.scope import ScopeService

logger = structlog.get_logger()

router = APIRouter(prefix="/scopes", tags=["Scopes"])


@router.post("", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
async def create_scope(
    payload: ScopeCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScopeResponse:
    """Register a new permission scope."""
    service = ScopeService(session)
    try:
        scope = await service.create_scope(
            name=payload.name,
            description=payload.description,
            category=payload.category,
        )
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "error_description": f"Scope '{payload.name}' already exists"},
        )
    return ScopeResponse.model_validate(scope)


@router.get("", response_model=ScopeListResponse)
async def list_scopes(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScopeListResponse:
    """List all registered scopes."""
    service = ScopeService(session)
    scopes = await service.get_all_scopes()
    return ScopeListResponse(
        data=[ScopeResponse.model_validate(s) for s in scopes],
        total=len(scopes),
    )


@router.post("/resolve", response_model=ScopeResolveResponse)
async def resolve_scopes(
    requested: list[str],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ScopeResolveResponse:
    """Resolve wildcard scopes to concrete scope names."""
    service = ScopeService(session)
    resolved = await service.resolve_scopes(requested)
    return ScopeResolveResponse(requested=requested, resolved=resolved)
