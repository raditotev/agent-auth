"""Well-known metadata endpoint (Task 4.6).

Follows OpenID Connect Discovery format adapted for agent authentication.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from agentauth.config import settings

router = APIRouter(tags=["Discovery"])


@router.get("/.well-known/agent-configuration")
async def agent_configuration() -> JSONResponse:
    """
    Agent authentication server metadata discovery endpoint.

    Modelled after OpenID Connect Discovery (RFC 8414) but adapted for
    machine-to-machine agent authentication flows.
    """
    base = settings.issuer_url.rstrip("/")
    api_base = f"{base}{settings.api_v1_prefix}"

    metadata = {
        "issuer": settings.issuer_url,
        # Core endpoints
        "token_endpoint": f"{api_base}/auth/token",
        "token_introspection_endpoint": f"{api_base}/auth/token/introspect",
        "token_revocation_endpoint": f"{api_base}/auth/token/revoke",
        "jwks_uri": f"{api_base}/auth/jwks",
        # Agent management
        "registration_endpoint": f"{api_base}/agents/bootstrap",
        "quickstart_endpoint": f"{api_base}/agents/quickstart",
        "agent_registration_endpoint": f"{api_base}/agents",
        # Scope & policy discovery
        "scopes_endpoint": f"{api_base}/scopes",
        "policy_syntax_endpoint": f"{api_base}/policies/syntax",
        "scopes_supported": [
            "agents.read", "agents.write", "agents.delete",
            "credentials.read", "credentials.write", "credentials.delete",
            "tokens.issue", "tokens.introspect", "tokens.revoke",
            "policies.read", "policies.write", "policies.delete",
            "delegations.read", "delegations.write", "delegations.delete",
            "files.read", "files.write", "files.delete",
            "email.send", "email.read",
            "admin.full",
            "api.read", "api.write",
        ],
        "grant_types_supported": [
            "client_credentials",
            "refresh_token",
            "agent_delegation",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
        ],
        # Token endpoint accepts both content types
        "token_endpoint_content_types_supported": [
            "application/x-www-form-urlencoded",
            "application/json",
        ],
        "response_types_supported": ["token"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_signing_alg_values_supported": ["RS256", "ES256"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "jti",
            "scopes", "agent_type", "trust_level",
            "parent_agent_id", "delegation_chain", "token_type",
        ],
        # Token lifetime hints (in seconds)
        "token_lifetimes": {
            "access_token_seconds": settings.access_token_expire_minutes * 60,
            "refresh_token_days": settings.refresh_token_expire_days,
            "refresh_buffer_seconds": 60,
        },
        "service_documentation": f"{base}/docs",
        "agent_types_supported": ["orchestrator", "autonomous", "assistant", "tool"],
        "trust_levels_supported": ["root", "delegated", "ephemeral"],
    }

    return JSONResponse(
        content=metadata,
        headers={"Cache-Control": "public, max-age=3600"},
    )
