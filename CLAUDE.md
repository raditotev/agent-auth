# AgentAuth — Identity & Authentication for Agents

## Claude Code Project Plan

> "Auth0, but for agents." A service that issues verifiable agent credentials, manages API key lifecycles, and provides OAuth-like flows designed for machine-to-machine interactions.

---

## 1. Project Overview

### Problem Statement

As AI agents proliferate across enterprises and the open ecosystem, a critical infrastructure gap has emerged: agents have no standardized way to prove who they are, who authorized them, and what they're allowed to do. Current human-centric identity systems (OAuth 2.0, SAML, OIDC) assume a browser, a human at the keyboard, and consent screens — none of which apply to autonomous agents operating on behalf of users or organizations.

### What AgentAuth Solves

- **Agent Identity**: Cryptographically verifiable credentials that uniquely identify an agent, its version, its owner, and its capabilities.
- **Delegated Authorization**: A human or organization authorizes an agent to act on their behalf with scoped, time-limited, revocable permissions.
- **Machine-to-Machine Auth Flows**: OAuth-like grant types purpose-built for agents talking to APIs, other agents, and tool providers.
- **API Key Lifecycle Management**: Issuance, rotation, revocation, and audit of API keys that agents use.
- **Trust & Attestation**: Verifiable claims about an agent's provenance, runtime environment, and behavioral constraints.

### Target Users

- Developers building AI agents that need to authenticate with third-party APIs
- Enterprises deploying internal agents that access sensitive systems
- Agent platforms / orchestrators that manage fleets of agents
- API providers who want to offer agent-friendly authentication
- Tool/MCP server providers who need to verify calling agents

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgentAuth Platform                       │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  Identity     │  │  AuthZ       │  │  Credential        │    │
│  │  Service      │  │  Engine      │  │  Manager           │    │
│  │              │  │              │  │                    │    │
│  │ - Agent reg  │  │ - Policy eng │  │ - JWT/JWK issuer  │    │
│  │ - Owner bind │  │ - Scope mgmt │  │ - API key lifecycle│    │
│  │ - DID support│  │ - Consent    │  │ - mTLS certs      │    │
│  └──────┬───────┘  └──────┬───────┘  └────────┬───────────┘    │
│         │                 │                    │                │
│  ┌──────┴─────────────────┴────────────────────┴───────────┐    │
│  │                    Core Token Service                    │    │
│  │  - Token minting (JWT, PASETO, DPoP)                   │    │
│  │  - Token introspection & validation                     │    │
│  │  - Refresh & rotation                                   │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│  ┌──────────────────────┴──────────────────────────────────┐    │
│  │                    Audit & Observability                  │    │
│  │  - Auth event log  - Usage analytics  - Anomaly detect  │    │
│  └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
          │                    │                     │
     ┌────┴────┐         ┌────┴────┐          ┌─────┴─────┐
     │  Agent  │         │  API /  │          │  Other    │
     │  SDK    │         │  Tool   │          │  Agents   │
     │         │         │Provider │          │           │
     └─────────┘         └─────────┘          └───────────┘
```

---

## 3. Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Language** | Python 3.12+ | Ecosystem alignment with AI/agent community |
| **Package Manager** | `uv` | Fast, modern Python package management |
| **Web Framework** | FastAPI | Async-first, OpenAPI spec auto-generation |
| **Database** | PostgreSQL 16 | ACID compliance, JSONB for flexible metadata |
| **ORM** | SQLAlchemy 2.0 + Alembic | Async support, mature migrations |
| **Cache / Rate Limit** | Redis 7 | Token caching, rate limiting, session store |
| **Crypto** | PyJWT + cryptography | Token signing, key management |
| **Task Queue** | Celery + Redis | Async key rotation, webhook delivery |
| **Containerization** | Docker + Docker Compose | Local dev parity, deployment |
| **Testing** | pytest + pytest-asyncio + httpx | Async test support, API testing |
| **CI/CD** | GitHub Actions | Automation, secret management |
| **Docs** | MkDocs Material | Developer documentation |
| **Observability** | Structlog + OpenTelemetry | Structured logging, distributed tracing |

---

## 4. Project Structure

```
agentauth/
├── CLAUDE.md                     # Claude Code project instructions
├── pyproject.toml                # uv project config
├── uv.lock                       # lockfile
├── alembic.ini                   # migrations config
├── docker-compose.yml            # local dev services
├── Dockerfile                    # app container
├── Makefile                      # common commands
│
├── src/
│   └── agentauth/
│       ├── __init__.py
│       ├── main.py               # FastAPI app factory
│       ├── config.py             # Pydantic settings
│       ├── dependencies.py       # FastAPI dependency injection
│       │
│       ├── models/               # SQLAlchemy models
│       │   ├── __init__.py
│       │   ├── agent.py          # Agent identity (sole principal)
│       │   ├── credential.py     # API keys, tokens
│       │   ├── policy.py         # Authorization policies
│       │   ├── scope.py          # Permission scopes
│       │   ├── delegation.py     # Delegation chains
│       │   └── audit.py          # Audit log entries
│       │
│       ├── schemas/              # Pydantic request/response schemas
│       │   ├── __init__.py
│       │   ├── agent.py
│       │   ├── auth.py
│       │   ├── credential.py
│       │   ├── policy.py
│       │   └── token.py
│       │
│       ├── api/                  # Route handlers
│       │   ├── __init__.py
│       │   ├── v1/
│       │   │   ├── __init__.py
│       │   │   ├── agents.py     # Agent CRUD
│       │   │   ├── auth.py       # Auth flows (token exchange)
│       │   │   ├── credentials.py # API key management
│       │   │   ├── policies.py   # Policy CRUD
│       │   │   ├── scopes.py     # Scope management
│       │   │   ├── delegations.py # Delegation management
│       │   │   ├── wellknown.py  # .well-known endpoints
│       │   │   └── admin.py      # Admin operations
│       │   └── middleware.py     # Auth, rate limit, logging
│       │
│       ├── services/             # Business logic
│       │   ├── __init__.py
│       │   ├── identity.py       # Agent registration & lookup
│       │   ├── token.py          # Token minting & validation
│       │   ├── credential.py     # API key lifecycle
│       │   ├── authorization.py  # Policy evaluation engine
│       │   ├── delegation.py     # Delegation chain management
│       │   ├── crypto.py         # Key generation, signing
│       │   ├── audit.py          # Audit event recording
│       │   └── webhook.py        # Event notification delivery
│       │
│       ├── core/                 # Shared infrastructure
│       │   ├── __init__.py
│       │   ├── database.py       # Async engine & session
│       │   ├── redis.py          # Redis client
│       │   ├── security.py       # Hashing, encryption utils
│       │   ├── exceptions.py     # Custom exception hierarchy
│       │   └── telemetry.py      # OpenTelemetry setup
│       │
│       └── tasks/                # Celery async tasks
│           ├── __init__.py
│           ├── key_rotation.py   # Scheduled key rotation
│           ├── cleanup.py        # Expired token cleanup
│           └── webhooks.py       # Webhook dispatch
│
├── migrations/                   # Alembic migrations
│   ├── env.py
│   └── versions/
│
├── tests/
│   ├── conftest.py               # Fixtures, test DB
│   ├── unit/
│   │   ├── test_token_service.py
│   │   ├── test_policy_engine.py
│   │   ├── test_credential_service.py
│   │   └── test_crypto.py
│   ├── integration/
│   │   ├── test_auth_flows.py
│   │   ├── test_agent_lifecycle.py
│   │   └── test_delegation_chain.py
│   └── e2e/
│       ├── test_full_auth_flow.py
│       └── test_multi_agent.py
│
├── sdk/                          # Python SDK for consumers
│   ├── pyproject.toml
│   └── src/
│       └── agentauth_sdk/
│           ├── __init__.py
│           ├── client.py
│           ├── credentials.py
│           └── middleware.py     # FastAPI/Flask middleware
│
└── docs/
    ├── mkdocs.yml
    └── docs/
        ├── index.md
        ├── quickstart.md
        ├── concepts/
        │   ├── agent-identity.md
        │   ├── delegation.md
        │   └── scopes.md
        ├── guides/
        │   ├── register-agent.md
        │   ├── auth-flows.md
        │   └── key-management.md
        └── api-reference/
```

---

## 5. CLAUDE.md — Claude Code Configuration

This file lives at the project root and configures Claude Code's behavior across the repo:

```markdown
# AgentAuth — Claude Code Instructions

## Project Overview
AgentAuth is an identity and authentication service for AI agents.
It issues verifiable agent credentials, manages API key lifecycles,
and provides OAuth-like flows for machine-to-machine interactions.

## Tech Stack
- Python 3.12+, FastAPI, SQLAlchemy 2.0 (async), PostgreSQL, Redis
- Package manager: uv (ALWAYS use `uv` — never pip or poetry)
- Testing: pytest + pytest-asyncio + httpx

## Commands
- `uv run pytest` — run full test suite
- `uv run pytest tests/unit/` — unit tests only
- `uv run pytest tests/integration/` — integration tests (requires docker compose up)
- `uv run pytest -x -q` — stop on first failure, quiet output
- `uv run ruff check src/` — lint
- `uv run ruff format src/` — format
- `uv run mypy src/` — type check
- `uv run alembic upgrade head` — apply migrations
- `uv run alembic revision --autogenerate -m "description"` — new migration
- `uv run uvicorn agentauth.main:app --reload` — dev server

## Code Style & Conventions
- All database operations are async (use `async def`, `await session.execute()`)
- Use Pydantic v2 models for all request/response schemas
- Use `Annotated` types with FastAPI `Depends()` for dependency injection
- All API responses use envelope: `{"data": ..., "meta": {...}}`
- Errors follow RFC 7807 Problem Details format
- Use structlog for logging — never print()
- All secrets loaded from environment via pydantic-settings
- SQL queries use SQLAlchemy 2.0 style (select(), not session.query())
- Timestamps always UTC, stored as timezone-aware
- IDs are UUIDs (uuid7 for time-sortable)
- API versioning via URL prefix: /api/v1/

## Security Rules
- Never log secrets, tokens, or API keys (mask in structlog processors)
- All API key values hashed with argon2 before storage — only prefix stored in plain text
- JWTs signed with RS256 (RSA) for external, ES256 (ECDSA) for internal
- Token lifetimes: access=15min, refresh=7d, API keys=configurable
- Rate limiting enforced at middleware level via Redis sliding window
- All credential operations produce audit log entries

## Testing Conventions
- Each test file mirrors the source module it tests
- Use `@pytest.fixture` for shared setup; prefer factory fixtures
- Integration tests use testcontainers for Postgres & Redis
- Use `httpx.AsyncClient` for API tests (not TestClient)
- Naming: `test_<action>_<scenario>_<expected_outcome>`
- Always test both success and error paths
- Auth flow tests must verify token contents, not just 200 status

## Database
- Alembic for migrations — never manual DDL
- Migration naming: `NNNN_verb_noun.py` (e.g., `0002_add_delegation_table.py`)
- Always include downgrade in migrations
- Use PostgreSQL-specific features (JSONB, array types) where beneficial

## File Organization
- models/ = SQLAlchemy ORM models (database tables)
- schemas/ = Pydantic models (API contracts)
- services/ = Business logic (no HTTP concerns)
- api/ = Route handlers (thin — delegate to services)
- core/ = Shared infrastructure (DB, Redis, security utils)
```

---

## 6. Data Models

### Design Principle: Agent as the Sole Principal

There is no Owner table. Every entity in the system — whether it's a root-level orchestrator, a sub-agent, or a tool-calling worker — is an **Agent**. The hierarchy is modeled through self-referencing parent relationships and the Delegation table. A "root agent" is simply an agent with no parent (`parent_agent_id` is null), bootstrapped via an out-of-band credential or self-registration. This keeps the identity model uniform: policies, audit logs, tokens, and delegation chains never need to special-case "owner vs agent."

### Core Entities

**Agent** — The sole principal identity in the system:
- `id` (uuid7, PK)
- `parent_agent_id` (FK → Agent, nullable — null means root agent)
- `name` (str, unique per parent scope)
- `agent_type` (enum: orchestrator, autonomous, assistant, tool)
- `description` (text)
- `homepage_url` (str, optional)
- `metadata` (JSONB — runtime info, model version, capabilities, contact/billing refs)
- `public_key` (text — PEM-encoded, for verifying agent-signed requests)
- `trust_level` (enum: root, delegated, ephemeral)
- `status` (enum: active, suspended, revoked)
- `max_child_depth` (int, default 3 — how many levels of sub-agents this agent can spawn)
- `created_at`, `updated_at`

Root agents (`parent_agent_id = null`, `trust_level = root`) serve the role that "Owner" previously filled. They are the trust anchor for their subtree. If billing or contact information is ever needed, it lives in `metadata` on the root agent — not in a separate table.

**Credential** — API keys and client secrets:
- `id` (uuid7, PK)
- `agent_id` (FK → Agent)
- `type` (enum: api_key, client_secret, mtls_cert, bootstrap)
- `prefix` (str — first 8 chars, for identification in logs)
- `hash` (str — argon2 hash of full key value)
- `scopes` (array[str])
- `expires_at` (timestamptz, nullable)
- `last_used_at` (timestamptz)
- `last_rotated_at` (timestamptz)
- `revoked_at` (timestamptz, nullable)
- `metadata` (JSONB — IP allowlist, usage notes)
- `created_at`

The `bootstrap` credential type supports the self-registration flow: a temporary, minimal-scope credential that lets a new agent register itself and then exchange for a full credential.

**Policy** — Authorization rules:
- `id` (uuid7, PK)
- `created_by_agent_id` (FK → Agent — the agent that defined this policy)
- `name` (str)
- `effect` (enum: allow, deny)
- `subjects` (JSONB — agent IDs, tags, wildcard patterns)
- `resources` (JSONB — API endpoints, service names)
- `actions` (array[str] — read, write, execute, delegate, admin)
- `conditions` (JSONB — time windows, IP ranges, rate limits)
- `priority` (int — higher = evaluated first)
- `enabled` (bool)
- `created_at`, `updated_at`

Policies are scoped to the creating agent's subtree. A root agent can define policies for all its descendants. A mid-level agent can only constrain its own children (and can never grant more than it has).

**Delegation** — Authorization chain between agents:
- `id` (uuid7, PK)
- `delegator_agent_id` (FK → Agent — the agent granting authority)
- `delegate_agent_id` (FK → Agent — the agent receiving authority)
- `scopes` (array[str] — must be subset of delegator's effective scopes)
- `constraints` (JSONB — time bound, resource restrictions, max re-delegation depth)
- `chain_depth` (int — 0 = from a root agent, increments with each hop)
- `max_chain_depth` (int — prevents unbounded re-delegation)
- `expires_at` (timestamptz)
- `revoked_at` (timestamptz, nullable)
- `created_at`

No `delegator_type` enum needed — both sides are always agents. Scope attenuation is enforced: a delegation can only grant a subset of what the delegator holds. Revoking a delegation cascades to all downstream delegations and active tokens.

**AuditEvent** — Immutable log of security-relevant events:
- `id` (uuid7, PK)
- `event_type` (str — agent.created, token.issued, key.rotated, delegation.granted, etc.)
- `actor_type` (enum: agent, system)
- `actor_id` (uuid — always an agent ID, or null for system-initiated events)
- `target_type` (str — agent, credential, policy, delegation, token)
- `target_id` (uuid)
- `action` (str)
- `outcome` (enum: success, failure, denied)
- `metadata` (JSONB — IP, user agent, request details, parent chain)
- `created_at`

The `actor_type` enum drops `owner` — it's now just `agent` or `system`. Every action in the audit log traces back to an agent identity.

### Entity Relationship Summary

```
Agent (self-referencing via parent_agent_id)
  │
  ├── has many → Credential
  ├── has many → Policy (as creator, scoped to subtree)
  ├── has many → Delegation (as delegator)
  ├── has many → Delegation (as delegate)
  └── has many → AuditEvent (as actor)

Root Agent (parent_agent_id = null)
  └── is just an Agent with trust_level = root
      └── no special table, no special auth flow
```

---

## 7. API Design

### Authentication Endpoints

```
POST   /api/v1/auth/token              # Token exchange (multiple grant types)
POST   /api/v1/auth/token/introspect   # Token introspection (RFC 7662)
POST   /api/v1/auth/token/revoke       # Token revocation (RFC 7009)
GET    /api/v1/auth/jwks               # Public key set (RFC 7517)
GET    /.well-known/agent-configuration # Agent auth server metadata
```

### Agent Management

```
POST   /api/v1/agents                  # Register new agent (root or child)
POST   /api/v1/agents/bootstrap        # Self-register root agent (minimal creds)
GET    /api/v1/agents                  # List agents (scoped to caller's subtree)
GET    /api/v1/agents/{agent_id}       # Get agent details
PATCH  /api/v1/agents/{agent_id}       # Update agent
DELETE /api/v1/agents/{agent_id}       # Deactivate agent
GET    /api/v1/agents/{agent_id}/children    # List child agents
GET    /api/v1/agents/{agent_id}/credentials # List agent's credentials
```

### Credential Management

```
POST   /api/v1/credentials             # Issue new credential (returns raw key ONCE)
GET    /api/v1/credentials             # List credentials (masked)
GET    /api/v1/credentials/{cred_id}   # Get credential metadata
POST   /api/v1/credentials/{cred_id}/rotate  # Rotate (returns new key, revokes old)
DELETE /api/v1/credentials/{cred_id}   # Revoke credential
```

### Policy & Scopes

```
POST   /api/v1/policies                # Create policy
GET    /api/v1/policies                # List policies
GET    /api/v1/policies/{policy_id}    # Get policy
PUT    /api/v1/policies/{policy_id}    # Update policy
DELETE /api/v1/policies/{policy_id}    # Delete policy
POST   /api/v1/policies/evaluate       # Dry-run policy evaluation

POST   /api/v1/scopes                  # Register custom scope
GET    /api/v1/scopes                  # List scopes
```

### Delegations

```
POST   /api/v1/delegations             # Create delegation
GET    /api/v1/delegations             # List delegations
GET    /api/v1/delegations/{id}/chain  # View full delegation chain
DELETE /api/v1/delegations/{id}        # Revoke delegation (cascading)
```

### Admin & Observability

```
GET    /api/v1/audit/events            # Query audit log
GET    /api/v1/stats                   # Usage statistics
GET    /health                         # Health check
GET    /ready                          # Readiness check
```

### Auth Grant Types

The `/auth/token` endpoint supports these grant types:

1. **`client_credentials`** — Agent authenticates with its own API key or client secret. Standard M2M flow.
2. **`agent_delegation`** — Agent presents a delegation token from its parent agent, exchanging it for scoped access tokens.
3. **`agent_chain`** — Agent A delegates a subset of its permissions to Agent B. Agent B presents the chain to get tokens.
4. **`token_exchange`** (RFC 8693) — Exchange one token type for another (e.g., parent agent token → child agent token with reduced scope).

---

## 8. Implementation Phases

### Phase 1 — Foundation (Weeks 1–3)

**Goal**: Working server with agent registration and basic credential issuance.

| Task | Description | Claude Code Prompt Sketch |
|------|-------------|--------------------------|
| 1.1 Project scaffold | Initialize uv project, FastAPI app, Docker Compose (Postgres + Redis), health endpoint | `"Initialize a new Python project with uv. Set up FastAPI app factory in src/agentauth/main.py with health and readiness endpoints. Create docker-compose.yml with postgres:16 and redis:7. Add pyproject.toml with dependencies: fastapi, uvicorn, sqlalchemy[asyncio], asyncpg, redis, pydantic-settings, structlog. Configure ruff and mypy."` |
| 1.2 Database setup | SQLAlchemy async engine, Alembic config, base model class | `"Set up SQLAlchemy 2.0 async engine in core/database.py. Configure Alembic for async migrations. Create a BaseModel class with id (uuid7), created_at, updated_at columns. Use asyncpg as the driver."` |
| 1.3 Agent model + CRUD | Agent registration (root and child), listing, updates | `"Create Agent model with fields: parent_agent_id (self-referencing FK, nullable), name, agent_type (enum: orchestrator, autonomous, assistant, tool), description, public_key, trust_level (enum: root, delegated, ephemeral), status, max_child_depth, metadata (JSONB). Root agents have parent_agent_id=null and trust_level=root. Implement CRUD endpoints under /api/v1/agents. Add bootstrap registration endpoint for root agents. Add Alembic migration."` |
| 1.4 Credential issuance | API key generation, hashed storage, prefix display | `"Create Credential model. Implement POST /api/v1/credentials that generates a secure random API key (32 bytes, base62-encoded), stores argon2 hash, returns raw key exactly once in response. Support bootstrap credential type for self-registration flow. Implement list (masked) and revoke endpoints. Add audit event on every credential operation."` |
| 1.6 API key auth middleware | Authenticate requests via API key header | `"Create middleware that extracts API key from X-Agent-Key header, looks up by prefix, verifies argon2 hash, resolves the associated agent and its trust_level, and injects it into request state. Return 401 with RFC 7807 body on failure. Update last_used_at on success."` |

**Phase 1 Deliverable**: A root agent can self-register, receive an API key, register child agents, and authenticate requests.

---

### Phase 2 — Token Service & Auth Flows (Weeks 4–6)

**Goal**: Full token lifecycle with multiple grant types.

| Task | Description | Claude Code Prompt Sketch |
|------|-------------|--------------------------|
| 2.1 JWK management | RSA + ECDSA key pair generation, rotation, JWKS endpoint | `"Create crypto service that generates RSA-2048 and ES256 key pairs, stores them in DB with key ID and activation/expiration dates. Implement /auth/jwks endpoint serving public keys in JWK Set format. Add scheduled task for key rotation (new key every 30 days, old keys valid 60 more days)."` |
| 2.2 Token minting | JWT creation with agent claims | `"Create token service that mints JWTs with claims: iss, sub (agent_id), aud, exp, iat, jti, scopes, agent_type, trust_level, parent_agent_id, delegation_chain. Sign with current active RSA key. Support configurable expiry. Return token + metadata."` |
| 2.3 client_credentials grant | Standard M2M token exchange | `"Implement client_credentials grant on POST /auth/token. Agent authenticates with API key (or client_id + client_secret), receives access_token + refresh_token. Validate requested scopes against credential's allowed scopes. Record audit event."` |
| 2.4 Token introspection | RFC 7662 compliant endpoint | `"Implement POST /auth/token/introspect per RFC 7662. Accept token in body, return active status plus decoded claims. Cache introspection results in Redis (TTL = remaining token lifetime). Support both JWT and opaque token formats."` |
| 2.5 Token revocation | RFC 7009 compliant endpoint | `"Implement POST /auth/token/revoke per RFC 7009. Add revoked token JTI to Redis blocklist (TTL = original token expiry). Introspection checks blocklist before returning active=true. Support cascading revocation of refresh tokens."` |
| 2.6 Refresh token flow | Rotating refresh tokens | `"Implement refresh_token grant type. On use, issue new access + refresh token pair, revoke the old refresh token. Detect refresh token reuse (replay attack) and revoke entire token family if detected. Store token family lineage in Redis."` |

**Phase 2 Deliverable**: Agents can obtain, refresh, introspect, and revoke tokens.

---

### Phase 3 — Authorization & Policy Engine (Weeks 7–9)

**Goal**: Fine-grained authorization with policy-based access control.

| Task | Description | Claude Code Prompt Sketch |
|------|-------------|--------------------------|
| 3.1 Scope registry | Define and manage permission scopes | `"Create Scope model and CRUD endpoints. Scopes have a name (dotted notation: 'files.read', 'email.send'), description, and category. Seed default scopes. Scopes can be hierarchical — 'files.*' implies 'files.read' and 'files.write'. Implement scope resolution logic."` |
| 3.2 Policy model + CRUD | Create and manage authorization policies | `"Create Policy model with fields: effect (allow/deny), subjects (JSONB for agent patterns), resources (JSONB for API patterns), actions (array), conditions (JSONB for time, IP, rate limits), priority. Implement CRUD endpoints. Validate policy consistency on create/update."` |
| 3.3 Policy evaluation engine | Evaluate whether an agent action is authorized | `"Create authorization service with evaluate(agent, action, resource, context) method. Load applicable policies ordered by priority. Implement deny-overrides combining algorithm: if any deny matches, deny. If any allow matches, allow. Otherwise deny (default deny). Cache compiled policies in Redis. Add POST /policies/evaluate for dry-run testing."` |
| 3.4 Auth middleware integration | Enforce policies on every API call | `"Create FastAPI middleware that extracts agent identity from token, resolves requested action + resource from the route, calls policy evaluation engine, and returns 403 with details on denial. Add X-Authorization-Decision header for debugging."` |
| 3.5 Delegation model + chain | Agent → sub-agent delegation | `"Create Delegation model. Implement delegation creation that validates: delegator has the scopes being delegated, chain depth doesn't exceed max, scopes are a subset of delegator's effective scopes. Both delegator and delegate are always agents (no special-casing). Implement chain traversal to compute effective permissions. Add cascading revocation (revoking a delegation revokes all downstream)."` |
| 3.6 agent_delegation grant | Token exchange with delegation proof | `"Implement agent_delegation grant type. Agent presents delegation_token (proving parent agent authorized it) plus its own credential. Service validates the delegation chain, computes effective scopes (intersection of all links in chain), and issues an access token with those scopes. Include delegation_chain claim in issued JWT."` |

**Phase 3 Deliverable**: Agents have scoped, policy-controlled access with delegation chains.

---

### Phase 4 — SDK, Observability & Hardening (Weeks 10–12)

**Goal**: Production-ready with developer SDK and operational tooling.

| Task | Description | Claude Code Prompt Sketch |
|------|-------------|--------------------------|
| 4.1 Python SDK | Client library for agent developers | `"Create agentauth-sdk Python package in sdk/ directory. Implement AgentAuthClient with methods: authenticate(), get_token(), refresh_token(), introspect(). Add automatic token refresh with configurable buffer. Include FastAPI middleware (AgentAuthMiddleware) that validates incoming tokens. Add retry logic with exponential backoff."` |
| 4.2 Verification middleware | Drop-in middleware for API providers | `"Add verify_agent() dependency for FastAPI that extracts Bearer token, fetches JWKS (cached), validates signature + claims, checks scopes against route requirements, and injects AgentIdentity into request. Implement scope decorators: @requires_scope('files.read')."` |
| 4.3 Audit log query API | Search and filter audit events | `"Implement GET /audit/events with filters: event_type, actor_id, target_id, date range, outcome. Use cursor-based pagination. Add PostgreSQL GIN index on metadata JSONB. Support export as JSONL."` |
| 4.4 Rate limiting | Per-agent rate limiting with Redis | `"Implement sliding window rate limiting in Redis. Configurable per agent or per policy. Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. Return 429 with Retry-After header. Different limits for token endpoints vs. management API."` |
| 4.5 Webhook delivery | Notify external systems of auth events | `"Create webhook subscription model. Implement async webhook delivery via Celery with: HMAC-SHA256 signed payloads, exponential backoff retry (max 5 attempts), delivery log, and subscription management endpoints. Events: credential.rotated, agent.suspended, policy.violated, delegation.revoked."` |
| 4.6 Well-known metadata | Discovery endpoint | `"Implement /.well-known/agent-configuration endpoint that returns: issuer URL, token endpoint, jwks_uri, supported grant types, supported scopes, introspection endpoint, revocation endpoint, registration endpoint. Follow OpenID Connect Discovery format adapted for agent auth."` |

**Phase 4 Deliverable**: SDK usable by developers, full audit trail, production monitoring.

---

### Phase 5 — Advanced Features (Weeks 13–16)

| Task | Description |
|------|-------------|
| 5.1 Agent attestation | Verifiable claims about agent runtime (TEE support, model version, safety constraints). Issue attestation tokens that third parties can verify. |
| 5.2 DID support | Decentralized Identifiers for agents. Agents can have `did:agentauth:<id>` identifiers resolvable via DID document endpoint. |
| 5.3 mTLS client certificates | Issue X.509 client certificates for agents. Mutual TLS as an auth mechanism for high-security environments. |
| 5.4 Multi-tenant / Organization | Org-level management with team roles (admin, developer, viewer). Org-wide policies, shared scopes, agent inventory. |
| 5.5 Agent-to-agent auth | Protocol for two agents to mutually authenticate. Both present credentials, negotiate shared session, verify delegation chains from respective owners. |
| 5.6 Dashboard UI | React admin dashboard for managing agents, viewing audit logs, configuring policies, monitoring usage. |

---

## 9. Testing Strategy

### Test Pyramid

**Unit Tests (60%)** — Services, crypto, policy evaluation logic. Fully isolated with mocked DB/Redis.

**Integration Tests (30%)** — Full API flows with real Postgres + Redis via testcontainers. Test auth flows end-to-end within the service boundary.

**E2E Tests (10%)** — Multi-agent scenarios: root agent registers, gets credential, spawns child agent, child authenticates, delegates to sub-agent, sub-agent accesses resource.

### Key Test Scenarios

- Agent registration with duplicate name under same parent → 409 conflict
- API key issuance → verify raw key only in first response, hash matches
- API key rotation → old key immediately invalid, new key works
- Token exchange with expired credential → 401
- Token refresh with reused refresh token → entire token family revoked
- Policy deny overrides allow → 403 with policy ID in response
- Delegation chain exceeds max depth → 400
- Delegated scopes exceed delegator's scopes → 400
- Cascading revocation → all downstream delegations + tokens revoked
- Rate limit exceeded → 429 with correct headers
- Concurrent key rotation → no race conditions (use SELECT FOR UPDATE)

---

## 10. Security Considerations

- **Secret storage**: All API keys stored as argon2id hashes. Raw key shown once at creation. No recovery — only rotation.
- **Token signing**: RSA-2048 for external-facing JWTs (broad compatibility), ES256 for internal (performance). Key rotation every 30 days with 60-day overlap.
- **Replay protection**: Token JTI stored in Redis blocklist on revocation. Refresh token family tracking for reuse detection.
- **Delegation bounds**: Max chain depth (default 3). Scope attenuation only (can't escalate). Time-bounded. Revocation cascades.
- **Rate limiting**: Sliding window per agent per endpoint. Separate limits for auth endpoints (stricter). Credential operations have aggressive rate limits.
- **Audit**: Every security-relevant operation logged immutably. Audit table is append-only (no UPDATE/DELETE permissions on the DB role).
- **Input validation**: Pydantic strict mode. SQL injection prevented by SQLAlchemy parameterized queries. All string fields have max length.
