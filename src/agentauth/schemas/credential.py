"""Pydantic schemas for Credential API requests and responses."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from agentauth.models.credential import CredentialType


class CredentialCreate(BaseModel):
    """Schema for creating a new credential."""

    agent_id: UUID = Field(..., description="Agent ID for this credential")
    type: CredentialType = Field(
        default=CredentialType.API_KEY,
        description="Type of credential",
    )
    scopes: list[str] | None = Field(
        default=None,
        description="Permission scopes for this credential",
    )
    expires_at: datetime | None = Field(
        None,
        description="Expiration time (null = never expires)",
    )
    credential_metadata: dict[str, Any] | None = Field(
        default=None,
        alias="metadata",
        description="Flexible metadata (IP allowlist, usage notes, etc.)",
    )


class CredentialResponse(BaseModel):
    """Schema for credential response (masked)."""

    id: UUID
    agent_id: UUID
    type: CredentialType
    prefix: str = Field(..., description="First 8 characters for identification")
    scopes: list[str] | None
    expires_at: datetime | None
    last_used_at: datetime | None
    last_rotated_at: datetime | None
    revoked_at: datetime | None
    credential_metadata: dict[str, Any] | None = Field(
        None,
        alias="metadata",
    )
    created_at: datetime
    updated_at: datetime
    is_valid: bool = Field(..., description="Whether credential is currently valid")

    model_config = {
        "from_attributes": True,
        "populate_by_name": True,
    }


class CredentialCreateResponse(BaseModel):
    """Schema for credential creation response (includes raw key ONCE)."""

    credential: CredentialResponse
    raw_key: str = Field(
        ...,
        description="Full API key - SAVE THIS NOW, it will never be shown again",
    )
    message: str = Field(
        default="Save this API key securely - it will never be shown again",
    )


class CredentialListResponse(BaseModel):
    """Schema for credential list response."""

    data: list[CredentialResponse]
    meta: dict[str, Any] = Field(
        default_factory=lambda: {"total": 0, "page": 1, "page_size": 50}
    )


class CredentialDetailResponse(BaseModel):
    """Schema for credential detail response."""

    data: CredentialResponse
    meta: dict[str, Any] = Field(default_factory=dict)


class CredentialRotateResponse(BaseModel):
    """Schema for credential rotation response (includes new raw key)."""

    old_credential: CredentialResponse
    new_credential: CredentialResponse
    raw_key: str = Field(
        ...,
        description="New API key - SAVE THIS NOW, it will never be shown again",
    )
    message: str = Field(
        default="Old key revoked. Save new key securely - it will never be shown again",
    )
