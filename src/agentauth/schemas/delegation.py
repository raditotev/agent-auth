"""Pydantic schemas for delegation operations."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class DelegationCreate(BaseModel):
    """Request schema for creating a delegation."""

    delegate_agent_id: UUID = Field(..., description="Agent receiving the delegation")
    scopes: list[str] = Field(..., description="Scopes being delegated")
    constraints: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional constraints: expires_at, resource restrictions",
    )
    max_chain_depth: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum re-delegation depth",
    )
    expires_at: datetime | None = Field(None, description="Delegation expiry timestamp")


class DelegationResponse(BaseModel):
    """Response schema for a delegation."""

    id: UUID
    delegator_agent_id: UUID
    delegate_agent_id: UUID
    scopes: list[str]
    constraints: dict[str, Any]
    chain_depth: int
    max_chain_depth: int
    # max_absolute_chain_depth is an alias for max_chain_depth for self-documentation
    max_absolute_chain_depth: int
    # How many further re-delegation hops are permitted from the current delegate
    chain_depth_remaining: int
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime
    is_active: bool

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, delegation: object) -> "DelegationResponse":
        chain_depth: int = delegation.chain_depth  # type: ignore[attr-defined]
        max_chain_depth: int = delegation.max_chain_depth  # type: ignore[attr-defined]
        data = {
            "id": delegation.id,  # type: ignore[attr-defined]
            "delegator_agent_id": delegation.delegator_agent_id,  # type: ignore[attr-defined]
            "delegate_agent_id": delegation.delegate_agent_id,  # type: ignore[attr-defined]
            "scopes": delegation.scopes,  # type: ignore[attr-defined]
            "constraints": delegation.constraints,  # type: ignore[attr-defined]
            "chain_depth": chain_depth,
            "max_chain_depth": max_chain_depth,
            "max_absolute_chain_depth": max_chain_depth,
            "chain_depth_remaining": max(0, max_chain_depth - chain_depth),
            "expires_at": delegation.expires_at,  # type: ignore[attr-defined]
            "revoked_at": delegation.revoked_at,  # type: ignore[attr-defined]
            "created_at": delegation.created_at,  # type: ignore[attr-defined]
            "updated_at": delegation.updated_at,  # type: ignore[attr-defined]
            "is_active": delegation.is_active(),  # type: ignore[attr-defined]
        }
        return cls(**data)


class DelegationListResponse(BaseModel):
    """Paginated list of delegations."""

    data: list[DelegationResponse]
    total: int


class DelegationChainResponse(BaseModel):
    """Full delegation chain for an agent."""

    delegation_id: UUID
    chain: list[DelegationResponse]
    effective_scopes: list[str]
