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

## Quick Start

The MCP endpoint is **built into the AgentAuth API** — no separate server or local install required.

Add this to your MCP client config:

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

That's it. Every MCP-compatible client can connect with just a URL.

---

## Client Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

Restart Claude Desktop after saving.

### Claude Code (CLI)

Add to `.claude/settings.json` in your project root, or globally at `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

### Cursor

Edit `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project-scoped):

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

### GitHub Copilot (VS Code)

Add to VS Code `settings.json` (`Ctrl+Shift+P` → *Open User Settings (JSON)*):

```json
{
  "github.copilot.chat.mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

For workspace-scoped config, add the same block to `.vscode/settings.json`.

### Windsurf (Codeium)

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

### Continue.dev

Edit `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "agentauth",
      "url": "https://agentauth.radi.pro/mcp"
    }
  ]
}
```

### Zed

Edit `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "agentauth": {
      "url": "https://agentauth.radi.pro/mcp"
    }
  }
}
```

### OpenHands (formerly OpenDevin)

In `config.toml`:

```toml
[[mcp_servers]]
name = "agentauth"
url = "https://agentauth.radi.pro/mcp"
```

### Any MCP-compatible agent (Python SDK)

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("https://agentauth.radi.pro/mcp") as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
```

---

## Self-hosting

If you run your own AgentAuth instance, the MCP endpoint is automatically available at `/mcp`. No extra configuration needed — it's part of the main application.

```
https://your-agentauth-instance.com/mcp
```

The MCP server internally calls the AgentAuth REST API via `AGENTAUTH_URL`. When running as part of the main app, set this to the internal URL:

```env
AGENTAUTH_URL=http://127.0.0.1:8000
```

---

## Local (stdio) mode

For development or air-gapped environments, you can also run the MCP server locally as a stdio subprocess. This requires the package installed on the client machine.

```bash
cd mcp-server
uv pip install -e .
```

Then configure your MCP client with a command instead of a URL:

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

---

## Usage flow

A typical agent interaction looks like:

1. **First time** — call `quickstart` to register and get credentials
2. **Subsequent sessions** — call `authenticate` with saved API key to get a token
3. **During work** — use the token for `list_agents`, `create_delegation`, `check_permission`, etc.
4. **Before token expires** — call `refresh_token` (check `refresh_before` from authenticate response)
5. **When done** — optionally `revoke_token`

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTAUTH_URL` | Yes | Base URL of the AgentAuth service (e.g. `https://agentauth.radi.pro`) |
| `AGENTAUTH_API_KEY` | No | Default API key for the `authenticate` tool |

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run directly (stdio)
AGENTAUTH_URL=http://localhost:8000 python -m agentauth_mcp.server
```
