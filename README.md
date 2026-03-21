# AgentAuth

Identity and authentication service for AI agents. Issues verifiable credentials, manages API key lifecycles, and provides OAuth-like flows for machine-to-machine interactions.

## MCP Server

AgentAuth is available as an MCP (Model Context Protocol) server — no HTTP client code required. Any MCP-compatible agent can authenticate and manage permissions through standard tool calls.

The MCP endpoint is **built into the AgentAuth API** at `/mcp`. No separate install needed.

---

## Setup

### Hosted (recommended)

Add this to your MCP client config and you're done:

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

### Client-specific config locations

| Client | Config file |
|--------|------------|
| **Claude Desktop** (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Desktop** (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Claude Code** (project) | `.claude/settings.json` |
| **Claude Code** (global) | `~/.claude/settings.json` |
| **Cursor** (global) | `~/.cursor/mcp.json` |
| **Cursor** (project) | `.cursor/mcp.json` |
| **VS Code / Copilot** | User or workspace `settings.json` under `github.copilot.chat.mcpServers` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` |
| **Continue.dev** | `~/.continue/config.json` |
| **Zed** | `~/.config/zed/settings.json` under `context_servers` |

All use the same URL: `https://agentauth.radi.pro/mcp`

### Local / stdio mode

For development or air-gapped environments:

```bash
cd mcp-server
uv pip install -e .
```

```json
{
  "mcpServers": {
    "agentauth": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agent-auth/mcp-server", "agentauth-mcp"],
      "env": {
        "AGENTAUTH_URL": "https://agentauth.radi.pro"
      }
    }
  }
}
```

### Self-hosting

If you run your own AgentAuth instance, the MCP endpoint is automatically available at `/mcp`. Set `AGENTAUTH_URL` to your instance:

```env
AGENTAUTH_URL=https://your-agentauth-instance.com
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTAUTH_URL` | Yes (stdio mode) | Base URL of the AgentAuth service |
| `AGENTAUTH_API_KEY` | No | Default API key used by `authenticate` when none is passed |

When using the hosted `/mcp` endpoint directly, no environment variables are needed on the client.

---

## Typical Usage Flow

```
1. quickstart          → register agent + get API key + access token (first run only)
2. authenticate        → exchange saved API key for a fresh access token
3. [do work]           → pass access_token to list_agents, create_delegation, check_permission, etc.
4. refresh_token       → get a new token pair before the access token expires
5. revoke_token        → invalidate tokens when done (optional)
```

---

## Available Tools

### `discover`

Get AgentAuth server capabilities and endpoints.

Returns supported grant types, available scopes, token lifetimes, and all endpoint URLs. Call this first to understand what the service offers.

```
discover()
```

---

### `quickstart`

Register a new root agent and get credentials in one call. The fastest way to get started.

Returns agent identity, API key (shown **once** — save immediately), access token, refresh token, and expiry timestamps.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Human-readable agent name, e.g. `"my-data-pipeline"` |
| `agent_type` | string | Yes | One of: `orchestrator`, `autonomous`, `assistant`, `tool` |
| `description` | string | No | Purpose of the agent |

```
quickstart(
  name="my-pipeline",
  agent_type="autonomous",
  description="Processes nightly ETL jobs"
)
```

Response includes:
- `agent` — registered identity (id, name, agent_type, trust_level, …)
- `api_key` — raw API key, **save it now**
- `access_token` — ready-to-use Bearer token (valid 15 min)
- `refresh_token` — use before access token expires
- `expires_at` / `refresh_before` — ISO-8601 timestamps

---

### `authenticate`

Exchange an API key for an access token (client_credentials grant).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | No | AgentAuth API key. Falls back to `AGENTAUTH_API_KEY` env var |
| `scopes` | string[] | No | Scopes to request. Defaults to all scopes the credential allows |

```
authenticate(
  api_key="ak_live_...",
  scopes=["api.read", "agents.write"]
)
```

Returns: `access_token`, `refresh_token`, `token_type`, `expires_in`, `expires_at`, `refresh_before`

---

### `refresh_token`

Exchange a refresh token for a new access + refresh token pair.

Use when the access token is near expiry — check `refresh_before` from the `authenticate` response.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `refresh_token_value` | string | Yes | Refresh token from a previous `authenticate` or `quickstart` call |

```
refresh_token(refresh_token_value="rt_...")
```

---

### `introspect_token`

Check whether a token is valid and inspect its claims (RFC 7662).

Returns `active: true/false` plus decoded claims (scopes, agent_type, trust_level, expiration) if active.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The access or refresh token to inspect |

```
introspect_token(token="eyJ...")
```

---

### `revoke_token`

Revoke an access or refresh token immediately (RFC 7009).

The token is added to the blocklist and invalidated. Idempotent — revoking an already-revoked token succeeds.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Token to revoke |

```
revoke_token(token="eyJ...")
```

---

### `create_credential`

Issue a new API key for an agent.

The `raw_key` is returned **once** — save it immediately. Subsequent reads only show the key prefix.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | Yes | UUID of the agent |
| `access_token` | string | Yes | Bearer token |
| `scopes` | string[] | No | Optional scope restrictions for the new key |

```
create_credential(
  agent_id="01927...",
  access_token="eyJ...",
  scopes=["api.read"]
)
```

---

### `rotate_credential`

Revoke an existing API key and issue a replacement in one atomic operation.

Returns new credential fields, the new `raw_key` (save it), and the old `credential_id`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `credential_id` | string | Yes | UUID of the credential to rotate |
| `access_token` | string | Yes | Bearer token |

```
rotate_credential(
  credential_id="01928...",
  access_token="eyJ..."
)
```

---

### `revoke_credential`

Permanently revoke an API key. **Irreversible.**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `credential_id` | string | Yes | UUID of the credential to revoke |
| `access_token` | string | Yes | Bearer token |

```
revoke_credential(
  credential_id="01928...",
  access_token="eyJ..."
)
```

---

### `create_delegation`

Delegate a subset of your permissions to another agent.

The delegate can only receive scopes the delegator already holds. Delegations can be chained up to `max_chain_depth` times.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegate_agent_id` | string | Yes | UUID of the agent receiving permissions |
| `scopes` | string[] | Yes | Scopes to delegate (must be a subset of your own) |
| `access_token` | string | Yes | Bearer token of the delegating agent |
| `max_chain_depth` | int | No | How many times the delegate can re-delegate (default: 3) |
| `expires_in_hours` | int | No | Delegation expiry in hours from now |

```
create_delegation(
  delegate_agent_id="01929...",
  scopes=["api.read", "agents.read"],
  access_token="eyJ...",
  max_chain_depth=1,
  expires_in_hours=24
)
```

---

### `check_permission`

Dry-run policy evaluation — checks whether an agent is allowed to perform an action without actually enforcing it. Useful for pre-flight checks.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | Yes | UUID of the agent to check |
| `action` | string | Yes | One of: `read`, `write`, `delete`, `execute`, `delegate`, `admin` |
| `resource` | string | Yes | Resource path, e.g. `"/api/v1/credentials"` |
| `access_token` | string | Yes | Bearer token |

```
check_permission(
  agent_id="01927...",
  action="write",
  resource="/api/v1/credentials",
  access_token="eyJ..."
)
```

Returns: `allowed: true/false`, matched policy details, decision reasoning.

---

### `list_agents`

List registered agents with pagination.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `access_token` | string | Yes | Bearer token |
| `limit` | int | No | Max results, 1–100 (default: 50) |
| `offset` | int | No | Pagination offset (default: 0) |

```
list_agents(access_token="eyJ...", limit=10, offset=0)
```

---

### `get_agent`

Get full details for a specific agent.

Returns agent fields (id, name, agent_type, trust_level, status) merged with metadata (is_root, is_active).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string | Yes | UUID of the agent |
| `access_token` | string | Yes | Bearer token |

```
get_agent(agent_id="01927...", access_token="eyJ...")
```

---

## Agent Types

| Type | Description |
|------|-------------|
| `orchestrator` | Coordinates other agents; high-trust |
| `autonomous` | Self-directed agents running long tasks |
| `assistant` | Interactive agents responding to user requests |
| `tool` | Narrow-purpose utility agents |

---

## Token Lifetimes

| Token | Default lifetime |
|-------|-----------------|
| Access token | 15 minutes |
| Refresh token | 7 days |
| API keys | Configurable (no default expiry) |

---

## Python SDK Example

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("https://agentauth.radi.pro/mcp") as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # Register and get credentials
        result = await session.call_tool("quickstart", {
            "name": "my-agent",
            "agent_type": "autonomous",
        })
        api_key = result.content[0].text  # save this

        # Authenticate on subsequent runs
        auth = await session.call_tool("authenticate", {"api_key": api_key})
        token = auth.content[0].text  # access_token
```

---

## REST API

The MCP server wraps the AgentAuth REST API. Interactive API docs are available at:

```
https://agentauth.radi.pro/docs
```
