"""Pydantic schemas for token operations."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from agentauth.models.agent import AgentType, TrustLevel


class TokenClaims(BaseModel):
    """JWT token claims structure."""

    # Standard JWT claims (RFC 7519)
    iss: str = Field(..., description="Issuer")
    sub: str = Field(..., description="Subject (agent_id)")
    aud: str | list[str] = Field(..., description="Audience")
    exp: int = Field(..., description="Expiration time (Unix timestamp)")
    iat: int = Field(..., description="Issued at (Unix timestamp)")
    jti: str = Field(..., description="JWT ID (unique token identifier)")

    # Custom AgentAuth claims
    scopes: list[str] = Field(default_factory=list, description="Permission scopes")
    agent_type: AgentType = Field(..., description="Type of agent")
    trust_level: TrustLevel = Field(..., description="Trust level of agent")
    parent_agent_id: UUID | None = Field(None, description="Parent agent ID (null for root)")
    delegation_chain: list[UUID] | None = Field(
        None, description="Chain of delegation from root agent"
    )
    token_type: str = Field(default="access", description="Type of token (access/refresh)")
    access_token_jti: str | None = Field(None, description="JTI of paired access token (refresh tokens only)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "iss": "https://agentauth.example.com",
                "sub": "550e8400-e29b-41d4-a716-446655440000",
                "aud": "https://api.example.com",
                "exp": 1704067200,
                "iat": 1704066300,
                "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "scopes": ["files.read", "files.write"],
                "agent_type": "autonomous",
                "trust_level": "delegated",
                "parent_agent_id": "660e8400-e29b-41d4-a716-446655440000",
                "delegation_chain": [
                    "660e8400-e29b-41d4-a716-446655440000",
                    "550e8400-e29b-41d4-a716-446655440000",
                ],
                "token_type": "access",
            }
        }
    }


class TokenResponse(BaseModel):
    """Response containing issued tokens."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str | None = Field(None, description="JWT refresh token (optional)")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    scope: str | None = Field(None, description="Space-separated scopes")

    # Token metadata
    issued_at: datetime = Field(..., description="Token issuance timestamp")
    expires_at: datetime = Field(..., description="Access token expiration timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9...",
                "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9...",
                "token_type": "Bearer",
                "expires_in": 900,
                "scope": "files.read files.write",
                "issued_at": "2024-01-01T12:00:00Z",
                "expires_at": "2024-01-01T12:15:00Z",
            }
        }
    }


class TokenMetadata(BaseModel):
    """Additional metadata about a token."""

    key_id: str = Field(..., description="Signing key ID used")
    algorithm: str = Field(..., description="Signing algorithm")
    agent_id: UUID = Field(..., description="Agent ID (subject)")
    agent_name: str = Field(..., description="Agent name")
    agent_type: AgentType = Field(..., description="Agent type")
    trust_level: TrustLevel = Field(..., description="Trust level")
    scopes: list[str] = Field(default_factory=list, description="Granted scopes")


class TokenIntrospectionRequest(BaseModel):
    """RFC 7662 token introspection request."""

    token: str = Field(..., description="Token to introspect")
    token_type_hint: str | None = Field(
        None, description="Hint about token type (access_token/refresh_token)"
    )


class TokenIntrospectionResponse(BaseModel):
    """RFC 7662 token introspection response."""

    active: bool = Field(..., description="Whether token is active")

    # Optional claims (only present if active=true)
    scope: str | None = Field(None, description="Space-separated scopes")
    client_id: str | None = Field(None, description="Client/Agent identifier")
    username: str | None = Field(None, description="Agent name")
    token_type: str | None = Field(None, description="Token type")
    exp: int | None = Field(None, description="Expiration time")
    iat: int | None = Field(None, description="Issued at time")
    sub: str | None = Field(None, description="Subject")
    aud: str | list[str] | None = Field(None, description="Audience")
    iss: str | None = Field(None, description="Issuer")
    jti: str | None = Field(None, description="JWT ID")

    # Custom claims
    agent_type: str | None = Field(None, description="Agent type")
    trust_level: str | None = Field(None, description="Trust level")
    parent_agent_id: str | None = Field(None, description="Parent agent ID")

    model_config = {"extra": "ignore"}


class TokenRevocationRequest(BaseModel):
    """RFC 7009 token revocation request."""

    token: str = Field(..., description="Token to revoke")
    token_type_hint: str | None = Field(
        None, description="Hint about token type (access_token/refresh_token)"
    )


class TokenRequest(BaseModel):
    """Token request for various grant types."""

    grant_type: str = Field(..., description="OAuth grant type")
    scope: str | None = Field(None, description="Space-separated requested scopes")

    # For client_credentials grant
    client_id: str | None = Field(None, description="Client/Agent identifier")
    client_secret: str | None = Field(None, description="Client secret or API key")

    # For refresh_token grant
    refresh_token: str | None = Field(None, description="Refresh token")

    # For agent_delegation grant
    delegation_token: str | None = Field(None, description="Delegation token from parent")

    # For token_exchange grant (RFC 8693)
    subject_token: str | None = Field(None, description="Token to exchange")
    subject_token_type: str | None = Field(None, description="Type of subject token")
    requested_token_type: str | None = Field(None, description="Desired token type")
    audience: str | None = Field(None, description="Target audience")

    model_config = {"extra": "ignore"}


class TokenValidationResult(BaseModel):
    """Result of token validation."""

    valid: bool = Field(..., description="Whether token is valid")
    claims: TokenClaims | None = Field(None, description="Decoded token claims")
    error: str | None = Field(None, description="Error message if invalid")
    error_detail: dict[str, Any] | None = Field(None, description="Additional error details")


class JWKSResponse(BaseModel):
    """JSON Web Key Set response (RFC 7517)."""

    keys: list[dict[str, Any]] = Field(..., description="Array of JWK objects")

    model_config = {
        "json_schema_extra": {
            "example": {
                "keys": [
                    {
                        "kid": "abc123",
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
                        "e": "AQAB",
                    }
                ]
            }
        }
    }
