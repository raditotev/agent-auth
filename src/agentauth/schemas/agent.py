"""Pydantic schemas for Agent API requests and responses."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl

from agentauth.models.agent import AgentStatus, AgentType, TrustLevel
from agentauth.schemas.token import TokenResponse


class AgentBase(BaseModel):
    """Base agent schema with common fields."""

    name: str = Field(..., min_length=1, max_length=255, description="Agent name")
    agent_type: AgentType = Field(..., description="Type of agent")
    description: str | None = Field(None, description="Agent description")
    homepage_url: HttpUrl | None = Field(None, description="Agent homepage URL")
    public_key: str | None = Field(None, description="PEM-encoded public key")
    max_child_depth: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum levels of sub-agents this agent can spawn",
    )
    agent_metadata: dict[str, Any] | None = Field(
        default=None,
        alias="metadata",
        description="Flexible metadata (runtime info, capabilities, etc.)",
    )


class AgentCreate(AgentBase):
    """Schema for creating a new agent (child agent)."""

    parent_agent_id: UUID = Field(..., description="Parent agent ID")


class AgentBootstrapCreate(AgentBase):
    """Schema for bootstrapping a root agent."""

    # Root agents don't need parent_agent_id
    pass


class AgentUpdate(BaseModel):
    """Schema for updating an agent."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    homepage_url: HttpUrl | None = None
    public_key: str | None = None
    max_child_depth: int | None = Field(None, ge=0, le=10)
    agent_metadata: dict[str, Any] | None = Field(None, alias="metadata")


class AgentResponse(AgentBase):
    """Schema for agent response."""

    id: UUID
    parent_agent_id: UUID | None
    trust_level: TrustLevel
    status: AgentStatus
    deactivated_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
        "populate_by_name": True,
        # Exclude SQLAlchemy internal attributes
        "protected_namespaces": (),
    }


class AgentListResponse(BaseModel):
    """Schema for agent list response."""

    data: list[AgentResponse]
    meta: dict[str, Any] = Field(
        default_factory=lambda: {"total": 0, "page": 1, "page_size": 50}
    )


class AgentDetailResponse(BaseModel):
    """Schema for agent detail response (with additional context)."""

    data: AgentResponse
    meta: dict[str, Any] = Field(default_factory=dict)


class AgentQuickstartResponse(BaseModel):
    """
    Response for the /agents/quickstart endpoint.

    Contains everything a new agent needs to start making authenticated requests
    in a single call: agent identity, API key (shown once), and an access token.
    """

    agent: AgentResponse = Field(..., description="Registered root agent")
    api_key: str = Field(
        ...,
        description="Full API key — SAVE THIS NOW, it will never be shown again",
    )
    api_key_prefix: str = Field(..., description="API key prefix for identification")
    token: TokenResponse = Field(..., description="Ready-to-use access token")
    message: str = Field(
        default=(
            "Agent registered successfully. "
            "Save the api_key — it will never be shown again. "
            "Use token.access_token in the Authorization: Bearer header."
        )
    )
