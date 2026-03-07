# AgentAuth MCP Server

MCP (Model Context Protocol) server that exposes AgentAuth identity and authentication tools to any MCP-compatible AI agent.

## What it does

Instead of writing custom HTTP client code, any MCP-compatible agent (Claude, OpenAI Assistants, LangChain agents, etc.) can use AgentAuth through standard MCP tool calls:

- **discover** — Learn what the AgentAuth service offers
- **quickstart** — Register a new agent and get credentials in one call
- **authenticate** — Exchange an API key for an access token
- **refresh_token** — Refresh an expiring token
- **introspect_token** — Check if a token is valid
- **revoke_token** — Invalidate a token
- **create_credential** / **rotate_credential** / **revoke_credential** — API key lifecycle
- **create_delegation** — Delegate permissions to another agent
- **check_permission** — Pre-flight authorization check
- **list_agents** / **get_agent** — Agent discovery

## Setup

### Install

```bash
cd mcp-server
uv pip install -e .
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTAUTH_URL` | Yes | Base URL of the AgentAuth service (e.g. `http://localhost:8000`) |
| `AGENTAUTH_API_KEY` | No | Default API key for the `authenticate` tool |

### Claude Desktop / Claude Code

Add to your MCP config (`claude_desktop_config.json` or `.claude/settings.json`):

```json
{
  "mcpServers": {
    "agentauth": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/agent-auth/mcp-server", "agentauth-mcp"],
      "env": {
        "AGENTAUTH_URL": "http://localhost:8000",
        "AGENTAUTH_API_KEY": "agentauth_your_key_here"
      }
    }
  }
}
```

### Direct execution

```bash
AGENTAUTH_URL=http://localhost:8000 agentauth-mcp
```

## Usage flow

A typical agent interaction looks like:

1. **First time** — call `quickstart` to register and get credentials
2. **Subsequent sessions** — call `authenticate` with saved API key to get a token
3. **During work** — use the token for `list_agents`, `create_delegation`, `check_permission`, etc.
4. **Before token expires** — call `refresh_token` (check `refresh_before` from authenticate response)
5. **When done** — optionally `revoke_token`

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run directly
AGENTAUTH_URL=http://localhost:8000 python -m agentauth_mcp.server
```
