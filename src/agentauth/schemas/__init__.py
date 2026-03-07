"""Schemas package."""

from agentauth.schemas.agent import (
    AgentBootstrapCreate,
    AgentCreate,
    AgentDetailResponse,
    AgentListResponse,
    AgentQuickstartResponse,
    AgentResponse,
    AgentUpdate,
)
from agentauth.schemas.credential import (
    CredentialCreate,
    CredentialCreateResponse,
    CredentialDetailResponse,
    CredentialListResponse,
    CredentialResponse,
    CredentialRotateResponse,
)
from agentauth.schemas.delegation import (
    DelegationChainResponse,
    DelegationCreate,
    DelegationListResponse,
    DelegationResponse,
)
from agentauth.schemas.policy import (
    PolicyCreate,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdate,
)
from agentauth.schemas.scope import (
    ScopeCreate,
    ScopeListResponse,
    ScopeResolveResponse,
    ScopeResponse,
)
from agentauth.schemas.token import (
    JWKSResponse,
    TokenClaims,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    TokenMetadata,
    TokenRequest,
    TokenResponse,
    TokenRevocationRequest,
    TokenValidationResult,
)

__all__ = [
    # Agent
    "AgentCreate",
    "AgentBootstrapCreate",
    "AgentUpdate",
    "AgentResponse",
    "AgentListResponse",
    "AgentDetailResponse",
    "AgentQuickstartResponse",
    # Credential
    "CredentialCreate",
    "CredentialResponse",
    "CredentialCreateResponse",
    "CredentialListResponse",
    "CredentialDetailResponse",
    "CredentialRotateResponse",
    # Delegation
    "DelegationCreate",
    "DelegationResponse",
    "DelegationListResponse",
    "DelegationChainResponse",
    # Policy
    "PolicyCreate",
    "PolicyUpdate",
    "PolicyResponse",
    "PolicyListResponse",
    "PolicyEvaluateRequest",
    "PolicyEvaluateResponse",
    # Scope
    "ScopeCreate",
    "ScopeResponse",
    "ScopeListResponse",
    "ScopeResolveResponse",
    # Token
    "TokenClaims",
    "TokenResponse",
    "TokenMetadata",
    "TokenRequest",
    "TokenIntrospectionRequest",
    "TokenIntrospectionResponse",
    "TokenRevocationRequest",
    "TokenValidationResult",
    "JWKSResponse",
]
