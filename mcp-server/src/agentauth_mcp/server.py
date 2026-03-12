"""AgentAuth MCP Server.

Exposes AgentAuth identity, credential, token, delegation, and policy tools
so that any MCP-compatible AI agent can authenticate and manage permissions
without writing custom HTTP client code.

The MCP endpoint is automatically mounted at /mcp when running as part of
the main AgentAuth FastAPI application. For local development or air-gapped
environments, the server can also run standalone via stdio transport.

Configuration via environment variables:
    AGENTAUTH_URL     — Base URL of the AgentAuth service (required)
    AGENTAUTH_API_KEY — Default API key for the authenticate tool (optional)
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from mcp.server.fastmcp import FastMCP

from agentauth_mcp.client import AgentAuthHTTPClient

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

_client: AgentAuthHTTPClient | None = None


def _get_client() -> AgentAuthHTTPClient:
    global _client
    if _client is None:
        base_url = os.environ.get("AGENTAUTH_URL", "")
        if not base_url:
            raise RuntimeError(
                "AGENTAUTH_URL environment variable is required. "
                "Set it to the base URL of your AgentAuth service "
                "(e.g. https://agentauth.radi.pro)."
            )
        _client = AgentAuthHTTPClient(base_url)
    return _client


def _default_api_key() -> str | None:
    return os.environ.get("AGENTAUTH_API_KEY")


def _http_error(e: httpx.HTTPStatusError) -> dict:
    try:
        detail = e.response.json()
    except Exception:
        detail = e.response.text
    return {
        "error": f"HTTP {e.response.status_code}",
        "status_code": e.response.status_code,
        "detail": detail,
    }


@asynccontextmanager
async def _lifespan(_: FastMCP) -> AsyncIterator[None]:
    yield
    if _client is not None:
        await _client.close()


mcp = FastMCP(
    "AgentAuth",
    streamable_http_path="/",
    lifespan=_lifespan,
    instructions=(
        "This MCP server lets you interact with the AgentAuth identity and "
        "authentication service. Use the 'discover' tool first to learn "
        "about available endpoints and capabilities. Use 'quickstart' to "
        "register a new agent and get credentials in one call. Use "
        "'authenticate' to exchange an API key for an access token."
    ),
)


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
    try:
        return await _get_client().discover()
    except httpx.HTTPStatusError as e:
        return _http_error(e)


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

    This is the fastest way to get started. Returns a flat object:
    - agent: the registered agent identity (id, name, agent_type, trust_level, …)
    - api_key: raw API key — save it immediately, shown only once
    - access_token: ready-to-use Bearer token (valid 15 min)
    - refresh_token: use with refresh_token tool before access_token expires
    - expires_at / refresh_before: ISO-8601 timestamps for token lifecycle
    - token_type, expires_in: standard OAuth fields

    Args:
        name: Human-readable agent name (e.g. "my-data-pipeline")
        agent_type: One of: orchestrator, autonomous, assistant, tool
        description: Optional description of the agent's purpose
    """
    try:
        return await _get_client().quickstart(name, agent_type, description)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


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
    try:
        return await _get_client().list_agents(auth=access_token, limit=limit, offset=offset)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def get_agent(agent_id: str, access_token: str) -> dict:
    """Get details for a specific agent by ID.

    Returns agent fields (id, name, agent_type, trust_level, status, …)
    merged with metadata (is_root, is_active) in a single flat object.

    Args:
        agent_id: UUID of the agent
        access_token: Bearer token for authentication
    """
    try:
        return await _get_client().get_agent(agent_id, auth=access_token)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


# ---------------------------------------------------------------------------
# Tools — Authentication & Tokens
# ---------------------------------------------------------------------------


@mcp.tool()
async def authenticate(
    api_key: str | None = None,
    scopes: list[str] | None = None,
) -> dict:
    """Exchange an API key for an access token (client_credentials grant).

    Returns standard OAuth fields: access_token, refresh_token, token_type,
    expires_in, expires_at, refresh_before.

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
    try:
        return await client.authenticate(key, scopes)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def refresh_token(refresh_token_value: str) -> dict:
    """Exchange a refresh token for a new access + refresh token pair.

    Use this when your access token is about to expire (check the
    refresh_before timestamp from the authenticate response).

    Args:
        refresh_token_value: The refresh token from a previous authenticate call
    """
    try:
        return await _get_client().refresh_token(refresh_token_value)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def introspect_token(token: str) -> dict:
    """Check whether a token is valid and get its claims (RFC 7662).

    Returns active=true/false plus decoded claims (scopes, agent_type,
    trust_level, expiration, etc.) if the token is active.

    Args:
        token: The access or refresh token to introspect
    """
    try:
        return await _get_client().introspect_token(token)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def revoke_token(token: str) -> dict:
    """Revoke an access or refresh token (RFC 7009).

    The token is immediately invalidated and added to the blocklist.
    This operation is idempotent — revoking an already-revoked token succeeds.

    Args:
        token: The token to revoke
    """
    try:
        return await _get_client().revoke_token(token)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


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

    Returns credential fields (id, prefix, agent_id, scopes, …) with
    raw_key at the top level. The raw_key is shown ONCE — save it immediately.

    Args:
        agent_id: UUID of the agent to issue the key for
        access_token: Bearer token for authentication
        scopes: Optional scope restrictions for the new key
    """
    try:
        return await _get_client().create_credential(agent_id, auth=access_token, scopes=scopes)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def rotate_credential(credential_id: str, access_token: str) -> dict:
    """Rotate an API key — revokes old key and issues a new one.

    Returns the new credential fields (id, prefix, …) with raw_key and
    old_credential_id at the top level. The raw_key is shown ONCE.

    Args:
        credential_id: UUID of the credential to rotate
        access_token: Bearer token for authentication
    """
    try:
        return await _get_client().rotate_credential(credential_id, auth=access_token)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


@mcp.tool()
async def revoke_credential(credential_id: str, access_token: str) -> dict:
    """Revoke an API key. This action is irreversible.

    Args:
        credential_id: UUID of the credential to revoke
        access_token: Bearer token for authentication
    """
    try:
        return await _get_client().revoke_credential(credential_id, auth=access_token)
    except httpx.HTTPStatusError as e:
        return _http_error(e)


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
    try:
        return await _get_client().create_delegation(
            delegate_agent_id=delegate_agent_id,
            scopes=scopes,
            auth=access_token,
            max_chain_depth=max_chain_depth,
            expires_in_hours=expires_in_hours,
        )
    except httpx.HTTPStatusError as e:
        return _http_error(e)


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
    try:
        return await _get_client().check_permission(
            agent_id=agent_id,
            action=action,
            resource=resource,
            auth=access_token,
        )
    except httpx.HTTPStatusError as e:
        return _http_error(e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the AgentAuth MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
