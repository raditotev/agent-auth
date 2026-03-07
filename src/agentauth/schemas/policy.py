"""Pydantic schemas for policy operations."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from agentauth.models.policy import PolicyEffect


class PolicyCreate(BaseModel):
    """Request schema for creating a policy."""

    name: str = Field(..., description="Human-readable policy name")
    description: str = Field(default="", description="Policy description")
    effect: PolicyEffect = Field(default=PolicyEffect.ALLOW, description="allow or deny")
    subjects: dict = Field(
        default_factory=dict,
        description="Agent IDs / patterns this policy applies to",
    )
    resources: dict = Field(
        default_factory=dict,
        description="API endpoints / service names covered",
    )
    actions: list[str] = Field(
        default_factory=list,
        description="Actions: read, write, execute, delegate, admin",
    )
    conditions: dict = Field(
        default_factory=dict,
        description="Optional conditions: time windows, IP ranges, rate limits",
    )
    priority: int = Field(default=0, description="Evaluation priority (higher = first)")
    enabled: bool = Field(default=True, description="Whether the policy is active")


class PolicyUpdate(BaseModel):
    """Request schema for updating a policy."""

    name: str | None = None
    description: str | None = None
    effect: PolicyEffect | None = None
    subjects: dict | None = None
    resources: dict | None = None
    actions: list[str] | None = None
    conditions: dict | None = None
    priority: int | None = None
    enabled: bool | None = None


class PolicyResponse(BaseModel):
    """Response schema for a policy."""

    id: UUID
    created_by_agent_id: UUID
    name: str
    description: str
    effect: PolicyEffect
    subjects: dict
    resources: dict
    actions: list[str]
    conditions: dict
    priority: int
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PolicyListResponse(BaseModel):
    """Paginated list of policies."""

    data: list[PolicyResponse]
    total: int


class PolicyEvaluateRequest(BaseModel):
    """Request for dry-run policy evaluation."""

    agent_id: UUID = Field(..., description="Agent requesting access")
    action: str = Field(..., description="Action being attempted")
    resource: str = Field(..., description="Resource being accessed")
    context: dict = Field(default_factory=dict, description="Additional context")


class PolicyEvaluateResponse(BaseModel):
    """Result of policy evaluation."""

    allowed: bool
    effect: str
    matching_policy_id: UUID | None = None
    matching_policy_name: str | None = None
    reason: str
