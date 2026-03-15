# MCP Registry Publish Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the `agentauth-mcp-server` Python package to PyPI and list it on the MCP Registry so it is discoverable by AI agents and MCP-compatible clients.

**Architecture:** The MCP server (`mcp-server/`) is a standalone uv workspace member that already builds independently with hatchling. Publishing involves three sequential phases: (1) prep the package metadata and verification signal, (2) publish to PyPI manually to create the project, (3) wire up a GitHub Actions workflow that handles all future releases automatically using OIDC for both PyPI and the MCP Registry.

**Tech Stack:** uv, hatchling, PyPI, `mcp-publisher` CLI, GitHub Actions OIDC

---

## Chunk 1: Package Metadata & Verification Prep

### Task 1: Add PyPI ownership verification comment to README

**Files:**

- Modify: `mcp-server/README.md` (append one HTML comment near the top)

The MCP Registry verifies PyPI package ownership by looking for the string `mcp-name: <server-name>` anywhere in the README (hidden comments are fine). Without this, `mcp-publisher publish` will fail with "Registry validation failed for package".

- [ ] **Step 1: Add the verification comment to mcp-server/README.md**

  Open `mcp-server/README.md` and insert the following comment directly after the opening `# AgentAuth MCP Server` heading line:

  ```markdown
  <!-- mcp-name: io.github.radi-totev/agent-auth -->
  ```

  The file should begin:

  ```markdown
  # AgentAuth MCP Server

  <!-- mcp-name: io.github.radi-totev/agent-auth -->

  MCP (Model Context Protocol) server that exposes AgentAuth…
  ```

- [ ] **Step 2: Verify the comment is present**

  Run:

  ```bash
  grep "mcp-name" mcp-server/README.md
  ```

  Expected output:

  ```
  <!-- mcp-name: io.github.radi-totev/agent-auth -->
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add mcp-server/README.md
  git commit -m "chore(mcp-server): add MCP Registry ownership verification comment"
  ```

---

### Task 2: Complete pyproject.toml metadata for PyPI

**Files:**

- Modify: `mcp-server/pyproject.toml`

PyPI requires (and surfaces to users): `license`, `[project.urls]` with at minimum `Homepage` and `Repository`, and `readme` pointing to `README.md`. Without these, the PyPI listing is bare and the build may warn.

- [ ] **Step 1: Patch mcp-server/pyproject.toml**

  Add the following fields to the `[project]` table and add a `[project.urls]` table. The file currently has:

  ```toml
  [project]
  name = "agentauth-mcp-server"
  version = "0.1.0"
  description = "MCP server exposing AgentAuth identity and authentication tools for AI agents"
  requires-python = ">=3.12"
  ```

  Change it to:

  ```toml
  [project]
  name = "agentauth-mcp-server"
  version = "0.1.0"
  description = "MCP server exposing AgentAuth identity and authentication tools for AI agents"
  readme = "README.md"
  license = { text = "MIT" }
  requires-python = ">=3.12"

  [project.urls]
  Homepage = "https://agentauth.radi.pro"
  Repository = "https://github.com/radi-totev/agent-auth"
  ```

  > **Note:** If the repo is private or the GitHub username differs, adjust accordingly.

- [ ] **Step 2: Verify the build works with the new metadata**

  ```bash
  cd mcp-server && uv build
  ```

  Expected: a `dist/` directory is created containing a `.whl` and `.tar.gz` with no errors. The version printed should be `0.1.0`.

  ```bash
  ls dist/
  ```

  Expected:

  ```
  agentauth_mcp_server-0.1.0-py3-none-any.whl
  agentauth_mcp_server-0.1.0.tar.gz
  ```

- [ ] **Step 3: Commit**

  ```bash
  cd ..   # back to repo root
  git add mcp-server/pyproject.toml
  git commit -m "chore(mcp-server): add PyPI metadata (license, urls, readme)"
  ```

---

## Chunk 2: First Manual Publish (PyPI + MCP Registry)

> These steps are run **once** from your local machine. All future releases will be handled by GitHub Actions (Chunk 3).

### Task 3: Publish agentauth-mcp-server to PyPI

- [ ] **Step 1: Ensure you have a PyPI account and API token**
  - Go to [https://pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
  - Create a token scoped to "Entire account" (since the project doesn't exist yet)
  - Copy the token — it starts with `pypi-`

- [ ] **Step 2: Build the package**

  From the repo root:

  ```bash
  cd mcp-server && uv build
  ```

- [ ] **Step 3: Publish to PyPI**

  ```bash
  uv publish --token pypi-<YOUR_TOKEN_HERE>
  ```

  Expected output:

  ```
  Publishing agentauth_mcp_server-0.1.0-py3-none-any.whl to https://upload.pypi.org/legacy/
  Publishing agentauth_mcp_server-0.1.0.tar.gz to https://upload.pypi.org/legacy/
  ```

- [ ] **Step 4: Verify the package is live on PyPI**

  ```bash
  curl -s https://pypi.org/pypi/agentauth-mcp-server/json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['info']['name'], d['info']['version'])"
  ```

  Expected:

  ```
  agentauth-mcp-server 0.1.0
  ```

  Also visible at: `https://pypi.org/project/agentauth-mcp-server/`

---

### Task 4: Install mcp-publisher CLI

- [ ] **Step 1: Install via Homebrew (macOS)**

  ```bash
  brew install mcp-publisher
  ```

  Or via binary download:

  ```bash
  curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz mcp-publisher && sudo mv mcp-publisher /usr/local/bin/
  ```

- [ ] **Step 2: Verify installation**

  ```bash
  mcp-publisher --help
  ```

  Expected: help text showing `init`, `login`, `logout`, `publish` commands.

---

### Task 5: Create server.json

**Files:**

- Create: `server.json` (in repo root, not inside `mcp-server/`)

`server.json` is the registry manifest. It links the MCP Registry entry to the PyPI package and documents the env vars users need to set.

- [ ] **Step 1: Run mcp-publisher init (from repo root)**

  ```bash
  cd /path/to/agent-auth   # repo root
  mcp-publisher init
  ```

  This generates a `server.json` template. If it doesn't pick up the right values, create it manually.

- [ ] **Step 2: Edit server.json to match the following**

  ```json
  {
    "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
    "name": "io.github.radi-totev/agent-auth",
    "title": "AgentAuth",
    "description": "MCP server for AgentAuth — identity and authentication service for AI agents. Register agents, issue credentials, mint tokens, manage delegations, and check permissions via MCP tool calls.",
    "repository": {
      "url": "https://github.com/radi-totev/agent-auth",
      "source": "github"
    },
    "version": "0.1.0",
    "packages": [
      {
        "registryType": "pypi",
        "identifier": "agentauth-mcp-server",
        "version": "0.1.0",
        "transport": {
          "type": "stdio"
        },
        "environmentVariables": [
          {
            "name": "AGENTAUTH_URL",
            "description": "Base URL of the AgentAuth service (e.g. https://agentauth.radi.pro or http://localhost:8000 for self-hosted)",
            "isRequired": true,
            "isSecret": false,
            "format": "string"
          },
          {
            "name": "AGENTAUTH_API_KEY",
            "description": "Default API key for the authenticate tool. Optional — can also be passed per call.",
            "isRequired": false,
            "isSecret": true,
            "format": "string"
          }
        ]
      }
    ]
  }
  ```

- [ ] **Step 3: Verify server.json is valid JSON**

  ```bash
  python3 -c "import json; json.load(open('server.json')); print('valid')"
  ```

  Expected: `valid`

---

### Task 6: Authenticate and publish to MCP Registry

- [ ] **Step 1: Log in to MCP Registry via GitHub**

  ```bash
  mcp-publisher login github
  ```

  Follow the device-flow prompts: visit the URL printed in the terminal, enter the code, authorize, then return to terminal. Expected final output:

  ```
  Successfully authenticated!
  ✓ Successfully logged in
  ```

- [ ] **Step 2: Publish to MCP Registry**

  ```bash
  mcp-publisher publish
  ```

  Expected output:

  ```
  Publishing to https://registry.modelcontextprotocol.io...
  ✓ Successfully published
  ✓ Server io.github.radi-totev/agent-auth version 0.1.0
  ```

- [ ] **Step 3: Verify the registry entry is live**

  ```bash
  curl -s "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.radi-totev/agent-auth" | python3 -m json.tool
  ```

  Expected: JSON containing `"name": "io.github.radi-totev/agent-auth"` in the `servers` array.

- [ ] **Step 4: Commit server.json**

  ```bash
  git add server.json
  git commit -m "feat: add MCP Registry server.json manifest"
  ```

---

## Chunk 3: GitHub Actions Automation

### Task 7: GitHub Actions publish workflow

**Files:**

- Create: `.github/workflows/publish-mcp.yml`

This workflow fires on any `v*` tag push and:

1. Builds and publishes the Python package to PyPI (via OIDC trusted publisher)
2. Publishes the MCP Registry entry (via GitHub OIDC)

Both use OIDC so **no long-lived secrets are stored in GitHub**.

> **Before this workflow works**, you must configure PyPI trusted publishing once:
>
> 1. Go to [https://pypi.org/manage/project/agentauth-mcp-server/settings/publishing/](https://pypi.org/manage/project/agentauth-mcp-server/settings/publishing/)
> 2. Click "Add a new publisher"
> 3. Fill in: Owner = `radi-totev`, Repository = `agent-auth`, Workflow = `publish-mcp.yml`, Environment = (leave blank)
> 4. Save. PyPI will now accept OIDC tokens from this workflow.

- [ ] **Step 1: Create .github/workflows/publish-mcp.yml**

  ```yaml
  name: Publish MCP Server

  on:
    push:
      tags:
        - 'v*'

  jobs:
    publish:
      name: Build, publish to PyPI, and register with MCP Registry
      runs-on: ubuntu-latest
      permissions:
        id-token: write # Required for OIDC (both PyPI trusted publishing and mcp-publisher)
        contents: read

      steps:
        - name: Checkout
          uses: actions/checkout@v4

        - name: Set up uv
          uses: astral-sh/setup-uv@v5
          with:
            enable-cache: true

        - name: Extract version from tag
          id: version
          run: echo "version=${GITHUB_REF#refs/tags/v}" >> "$GITHUB_OUTPUT"

        - name: Set version in mcp-server/pyproject.toml
          run: |
            sed -i "s/^version = .*/version = \"${{ steps.version.outputs.version }}\"/" mcp-server/pyproject.toml

        - name: Set version in server.json
          run: |
            jq --arg v "${{ steps.version.outputs.version }}" \
              '.version = $v | .packages[0].version = $v' \
              server.json > server.tmp && mv server.tmp server.json

        - name: Build package
          working-directory: mcp-server
          run: uv build

        - name: Publish to PyPI (trusted publishing / OIDC)
          working-directory: mcp-server
          run: uv publish --trusted-publishing always

        - name: Install mcp-publisher
          run: |
            curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" \
              | tar xz mcp-publisher

        - name: Authenticate to MCP Registry (GitHub OIDC)
          run: ./mcp-publisher login github-oidc

        - name: Publish to MCP Registry
          run: ./mcp-publisher publish
  ```

- [ ] **Step 2: Commit the workflow file**

  ```bash
  git add .github/workflows/publish-mcp.yml
  git commit -m "ci: add GitHub Actions workflow to publish MCP server on version tags"
  ```

- [ ] **Step 3: Set up PyPI trusted publisher (one-time manual step)**

  Log in to PyPI, navigate to the project settings page, and add the trusted publisher as described in the note above. This step cannot be automated.

---

### Task 8: End-to-end release smoke test

Verify the full automation works by tagging a test release.

- [ ] **Step 1: Push a tag to trigger the workflow**

  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

  > If you already published `0.1.0` manually in Task 3, bump to `v0.1.1` first by updating the version in `mcp-server/pyproject.toml` and committing.

- [ ] **Step 2: Watch the workflow run**

  ```bash
  gh run watch
  ```

  Or visit: `https://github.com/radi-totev/agent-auth/actions`

  Expected: all steps green.

- [ ] **Step 3: Verify PyPI has the new version**

  ```bash
  curl -s https://pypi.org/pypi/agentauth-mcp-server/json | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['info']['version'])"
  ```

- [ ] **Step 4: Verify MCP Registry has the new version**

  ```bash
  curl -s "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.radi-totev/agent-auth" | python3 -m json.tool
  ```

---

## Validation Checklist (from task-10.1)

- [x] PyPI package accessible at `https://pypi.org/project/agentauth-mcp-server/`
- [x] `server.json` committed to repo root
- [x] `server.json` name matches `<!-- mcp-name: io.github.raditotev/agent-auth -->` comment in README
- [x] Registry entry discoverable: `curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.raditotev/agent-auth"`
- [x] `server.json` env vars: `AGENTAUTH_URL` (isRequired=true, isSecret=false), `AGENTAUTH_API_KEY` (isRequired=false, isSecret=true)
- [x] MCP server installable by a Claude Code user pointing at the public AgentAuth URL or self-hosted instance
- [x] GitHub Actions workflow publishes to PyPI and MCP Registry on `v*` tag push
