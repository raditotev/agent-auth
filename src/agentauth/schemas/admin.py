"""Pydantic schemas for Admin API."""

from pydantic import BaseModel, Field


class StatsData(BaseModel):
    """Stats counts for admin dashboard."""

    agents: int = Field(..., description="Total number of registered agents")
    credentials: int = Field(
        ...,
        description="Total number of credentials (API keys, client secrets, etc.)",
    )
    tokens_issued: int = Field(
        ...,
        description="Count of tokens minted (from token.issued audit events)",
    )


class StatsResponse(BaseModel):
    """Response for GET /stats endpoint."""

    data: StatsData = Field(..., description="Aggregate counts")
    meta: dict[str, object] = Field(default_factory=dict, description="Metadata")
