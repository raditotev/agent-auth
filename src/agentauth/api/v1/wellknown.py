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
        "token_endpoint": f"{api_base}/auth/token",
        "token_introspection_endpoint": f"{api_base}/auth/token/introspect",
        "token_revocation_endpoint": f"{api_base}/auth/token/revoke",
        "jwks_uri": f"{api_base}/auth/jwks",
        "registration_endpoint": f"{api_base}/agents/bootstrap",
        "agent_registration_endpoint": f"{api_base}/agents",
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
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
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
        "service_documentation": f"{base}/docs",
        "agent_types_supported": ["orchestrator", "autonomous", "assistant", "tool"],
        "trust_levels_supported": ["root", "delegated", "ephemeral"],
    }

    return JSONResponse(
        content=metadata,
        headers={"Cache-Control": "public, max-age=3600"},
    )
