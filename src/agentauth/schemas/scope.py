"""Pydantic schemas for scope operations."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class ScopeCreate(BaseModel):
    """Request schema for creating a scope."""

    name: str = Field(..., description="Scope name in dotted notation (e.g. 'files.read')")
    description: str = Field(default="", description="Human-readable description")
    category: str = Field(default="general", description="Category grouping")


class ScopeResponse(BaseModel):
    """Response schema for a scope."""

    id: UUID
    name: str
    description: str
    category: str
    is_default: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScopeListResponse(BaseModel):
    """Paginated list of scopes."""

    data: list[ScopeResponse]
    total: int


class ScopeResolveResponse(BaseModel):
    """Result of resolving wildcard scopes."""

    requested: list[str]
    resolved: list[str]
