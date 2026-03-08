# Quickstart: Zero to Authenticated in 60 Seconds

This guide walks through the fastest path to get an AI agent authenticated with AgentAuth.

## Prerequisites

- AgentAuth service running (e.g. `docker compose up`)
- `curl` or any HTTP client

## Option 1: One-call quickstart (recommended)

A single POST creates your agent, issues an API key, and returns an access token:

```bash
curl -X POST http://localhost:8000/api/v1/agents/quickstart \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-data-pipeline",
    "agent_type": "autonomous",
    "description": "Processes daily reports"
  }'
```

Response (save the `api_key` — it is shown only once):

```json
{
  "agent": {
    "id": "01938a7b-...",
    "name": "my-data-pipeline",
    "agent_type": "autonomous",
    "trust_level": "root",
    "status": "active",
    ...
  },
  "api_key": "agentauth_abc123def456...",
  "api_key_prefix": "agentaut",
  "token": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_before": "2024-01-01T12:14:00Z",
    ...
  },
  "message": "Agent registered successfully. Save the api_key..."
}
```

**No authentication required** — the quickstart endpoint is open for bootstrapping.

## Option 2: Step-by-step

### 1. Register a root agent

```bash
curl -X POST http://localhost:8000/api/v1/agents/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "agent_type": "orchestrator"
  }'
```

Save the `agent.id` from the response.

### 2. Create an API key

```bash
curl -X POST http://localhost:8000/api/v1/credentials \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: <any-existing-api-key>" \
  -d '{
    "agent_id": "<agent-id-from-step-1>",
    "type": "api_key"
  }'
```

Save the `raw_key` from the response.

### 3. Get an access token

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_secret": "<your-api-key>"
  }'
```

## Using your access token

All authenticated endpoints accept `Authorization: Bearer <token>`:

```bash
# List agents
curl http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer <access_token>"

# Create a child agent
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sub-agent",
    "agent_type": "tool",
    "parent_agent_id": "<your-agent-id>"
  }'
```

## Token refresh

Access tokens expire in 15 minutes. Check the `refresh_before` timestamp — refresh before that time:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "<your-refresh-token>"
  }'
```

## Using the Python SDK

```python
from agentauth_sdk import AgentAuthClient

async with AgentAuthClient(base_url="http://localhost:8000") as client:
    # First time: register and get everything
    result = await client.quickstart("my-agent", "autonomous")
    print(f"Save this API key: {result.api_key}")

    # The client now auto-manages tokens — just make requests
    agents = await client.list_agents()
```

For subsequent sessions, pass the saved API key:

```python
async with AgentAuthClient(
    base_url="http://localhost:8000",
    api_key="agentauth_abc123...",
) as client:
    # Tokens are obtained and refreshed automatically
    agents = await client.list_agents()
```

## Using the MCP Server

Add to your MCP config:

```json
{
  "mcpServers": {
    "agentauth": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agent-auth/mcp-server", "agentauth-mcp"],
      "env": {
        "AGENTAUTH_URL": "http://localhost:8000"
      }
    }
  }
}
```

Then any MCP-compatible agent can call tools like `quickstart`, `authenticate`, `check_permission`, etc. without writing any HTTP code.

## Service discovery

The well-known endpoint returns all available endpoints, scopes, and configuration:

```bash
curl http://localhost:8000/.well-known/agent-configuration
```

## What's next

- [Admin](./admin.md) — platform operator endpoints (stats, audit)
- [Delegation](./delegation.md) — delegate permissions to child agents
- [Policies](./policies.md) — create authorization rules
- [API Reference](../api-reference/) — full endpoint documentation
