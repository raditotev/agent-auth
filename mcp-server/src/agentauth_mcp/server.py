"""AgentAuth MCP Server.

Exposes AgentAuth identity, credential, token, delegation, and policy tools
so that any MCP-compatible AI agent can authenticate and manage permissions
without writing custom HTTP client code.

Configuration via environment variables:
    AGENTAUTH_URL  — Base URL of the AgentAuth service (required)
    AGENTAUTH_API_KEY — Default API key for authentication (optional)
"""

import os

from mcp.server.fastmcp import FastMCP

from agentauth_mcp.client import AgentAuthHTTPClient

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "AgentAuth",
    instructions=(
        "This MCP server lets you interact with the AgentAuth identity and "
        "authentication service. Use the 'discover' tool first to learn "
        "about available endpoints and capabilities. Use 'quickstart' to "
        "register a new agent and get credentials in one call. Use "
        "'authenticate' to exchange an API key for an access token."
    ),
)

_client: AgentAuthHTTPClient | None = None


def _get_client() -> AgentAuthHTTPClient:
    global _client
    if _client is None:
        base_url = os.environ.get("AGENTAUTH_URL", "")
        if not base_url:
            raise RuntimeError(
                "AGENTAUTH_URL environment variable is required. "
                "Set it to the base URL of your AgentAuth service "
                "(e.g. http://localhost:8000)."
            )
        _client = AgentAuthHTTPClient(base_url)
    return _client


def _default_api_key() -> str | None:
    return os.environ.get("AGENTAUTH_API_KEY")


# ---------------------------------------------------------------------------
# Tools — Discovery
# ---------------------------------------------------------------------------


@mcp.tool()
async def discover() -> dict:
    """Discover AgentAuth server capabilities and endpoints.

    Returns metadata about the AgentAuth service including supported
    grant types, available scopes, token lifetimes, and all endpoint URLs.
    Call this first to understand what the service offers.
    """
    client = _get_client()
    return await client.discover()


# ---------------------------------------------------------------------------
# Tools — Agent lifecycle
# ---------------------------------------------------------------------------


@mcp.tool()
async def quickstart(
    name: str,
    agent_type: str,
    description: str | None = None,
) -> dict:
    """Register a new root agent and get credentials in one call.

    This is the fastest way to get started. Returns:
    - The registered agent identity
    - An API key (save it — shown only once)
    - A ready-to-use access token

    Args:
        name: Human-readable agent name (e.g. "my-data-pipeline")
        agent_type: One of: orchestrator, autonomous, assistant, tool
        description: Optional description of the agent's purpose
    """
    client = _get_client()
    return await client.quickstart(name, agent_type, description)


@mcp.tool()
async def list_agents(
    access_token: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List registered agents.

    Args:
        access_token: Bearer token for authentication
        limit: Max results (1-100, default 50)
        offset: Pagination offset
    """
    client = _get_client()
    return await client.list_agents(auth=access_token, limit=limit, offset=offset)


@mcp.tool()
async def get_agent(agent_id: str, access_token: str) -> dict:
    """Get details for a specific agent by ID.

    Args:
        agent_id: UUID of the agent
        access_token: Bearer token for authentication
    """
    client = _get_client()
    return await client.get_agent(agent_id, auth=access_token)


# ---------------------------------------------------------------------------
# Tools — Authentication & Tokens
# ---------------------------------------------------------------------------


@mcp.tool()
async def authenticate(
    api_key: str | None = None,
    scopes: list[str] | None = None,
) -> dict:
    """Exchange an API key for an access token (client_credentials grant).

    Returns an access token, refresh token, and expiry metadata.
    The access token should be used in Authorization: Bearer headers
    for subsequent API calls.

    Args:
        api_key: AgentAuth API key. If omitted, uses AGENTAUTH_API_KEY env var.
        scopes: Optional list of scopes to request (e.g. ["api.read", "agents.write"]).
                If omitted, all scopes allowed by the credential are granted.
    """
    client = _get_client()
    key = api_key or _default_api_key()
    if not key:
        return {
            "error": "No API key provided and AGENTAUTH_API_KEY is not set. "
            "Either pass api_key or use 'quickstart' to register a new agent."
        }
    return await client.authenticate(key, scopes)


@mcp.tool()
async def refresh_token(refresh_token_value: str) -> dict:
    """Exchange a refresh token for a new access + refresh token pair.

    Use this when your access token is about to expire (check the
    refresh_before timestamp from the authenticate response).

    Args:
        refresh_token_value: The refresh token from a previous authenticate call
    """
    client = _get_client()
    return await client.refresh_token(refresh_token_value)


@mcp.tool()
async def introspect_token(token: str) -> dict:
    """Check whether a token is valid and get its claims (RFC 7662).

    Returns active=true/false plus decoded claims (scopes, agent_type,
    trust_level, expiration, etc.) if the token is active.

    Args:
        token: The access or refresh token to introspect
    """
    client = _get_client()
    return await client.introspect_token(token)


@mcp.tool()
async def revoke_token(token: str) -> dict:
    """Revoke an access or refresh token (RFC 7009).

    The token is immediately invalidated and added to the blocklist.
    This operation is idempotent — revoking an already-revoked token succeeds.

    Args:
        token: The token to revoke
    """
    client = _get_client()
    return await client.revoke_token(token)


# ---------------------------------------------------------------------------
# Tools — Credentials (API keys)
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_credential(
    agent_id: str,
    access_token: str,
    scopes: list[str] | None = None,
) -> dict:
    """Issue a new API key for an agent.

    The raw key is returned ONCE in the response — save it immediately.
    It cannot be retrieved later; only the key prefix is stored.

    Args:
        agent_id: UUID of the agent to issue the key for
        access_token: Bearer token for authentication
        scopes: Optional scope restrictions for the new key
    """
    client = _get_client()
    return await client.create_credential(agent_id, auth=access_token, scopes=scopes)


@mcp.tool()
async def rotate_credential(credential_id: str, access_token: str) -> dict:
    """Rotate an API key — revokes old key and issues a new one.

    The new raw key is returned ONCE. The old key is immediately invalid.

    Args:
        credential_id: UUID of the credential to rotate
        access_token: Bearer token for authentication
    """
    client = _get_client()
    return await client.rotate_credential(credential_id, auth=access_token)


@mcp.tool()
async def revoke_credential(credential_id: str, access_token: str) -> dict:
    """Revoke an API key. This action is irreversible.

    Args:
        credential_id: UUID of the credential to revoke
        access_token: Bearer token for authentication
    """
    client = _get_client()
    return await client.revoke_credential(credential_id, auth=access_token)


# ---------------------------------------------------------------------------
# Tools — Delegation
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_delegation(
    delegate_agent_id: str,
    scopes: list[str],
    access_token: str,
    max_chain_depth: int = 3,
    expires_in_hours: int | None = None,
) -> dict:
    """Delegate permissions to another agent.

    Creates a delegation from the authenticated agent (the delegator)
    to the specified delegate agent. The delegate can only receive a
    subset of the delegator's own scopes.

    Args:
        delegate_agent_id: UUID of the agent receiving permissions
        scopes: Scopes to delegate (must be subset of your own)
        access_token: Bearer token for the delegating agent
        max_chain_depth: How many times the delegate can re-delegate (default 3)
        expires_in_hours: Optional expiry in hours from now
    """
    client = _get_client()
    return await client.create_delegation(
        delegate_agent_id=delegate_agent_id,
        scopes=scopes,
        auth=access_token,
        max_chain_depth=max_chain_depth,
        expires_in_hours=expires_in_hours,
    )


# ---------------------------------------------------------------------------
# Tools — Authorization
# ---------------------------------------------------------------------------


@mcp.tool()
async def check_permission(
    agent_id: str,
    action: str,
    resource: str,
    access_token: str,
) -> dict:
    """Check if an agent is allowed to perform an action on a resource.

    Dry-run policy evaluation — does not enforce, only reports the decision.
    Useful for pre-flight permission checks before attempting an operation.

    Args:
        agent_id: UUID of the agent to check
        action: The action (read, write, delete, execute, delegate, admin)
        resource: The resource path (e.g. "/api/v1/credentials")
        access_token: Bearer token for authentication
    """
    client = _get_client()
    return await client.check_permission(
        agent_id=agent_id,
        action=action,
        resource=resource,
        auth=access_token,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the AgentAuth MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
