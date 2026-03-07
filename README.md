# AgentAuth

> Auth0, but for agents. Identity and authentication service for AI agents.

AgentAuth issues verifiable agent credentials, manages API key lifecycles, and provides OAuth-like flows designed for machine-to-machine interactions.

---

## Overview

As AI agents proliferate, a critical infrastructure gap has emerged: agents have no standardized way to prove who they are, who authorized them, and what they're allowed to do. AgentAuth fills this gap.

**What it provides:**

- **Agent Identity** — Cryptographically verifiable credentials that uniquely identify an agent, its version, its owner, and its capabilities
- **Delegated Authorization** — Scoped, time-limited, revocable permissions delegated from parent agents or root authorities
- **Machine-to-Machine Auth Flows** — OAuth-like grant types purpose-built for agents calling APIs, tools, and other agents
- **API Key Lifecycle Management** — Issuance, rotation, revocation, and audit of agent API keys
- **Policy-Based Access Control** — Fine-grained authorization with deny-override policy evaluation
- **Audit Trail** — Immutable log of every security-relevant event

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12+ |
| Package Manager | `uv` |
| Web Framework | FastAPI |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy 2.0 + Alembic |
| Cache / Rate Limit | Redis 7 |
| Crypto | PyJWT + cryptography |
| Task Queue | Celery + Redis |
| Testing | pytest + pytest-asyncio + httpx |

---

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker + Docker Compose

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd agent-auth

# Install dependencies
make dev

# Start Postgres and Redis
make up

# Copy environment file
cp .env.example .env

# Run database migrations
make migrate

# Start the development server
make run
```

The API will be available at `http://localhost:8000`.

Interactive docs: `http://localhost:8000/docs`

### Environment Variables

```env
# Application
APP_NAME=AgentAuth
ENVIRONMENT=development
DEBUG=false

# Database
DATABASE_URL=postgresql+asyncpg://agentauth:agentauth_dev_password@localhost:5432/agentauth

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# API
API_V1_PREFIX=/api/v1
CORS_ORIGINS=["*"]
```

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/token` | Token exchange (multiple grant types) |
| `POST` | `/api/v1/auth/token/introspect` | Token introspection (RFC 7662) |
| `POST` | `/api/v1/auth/token/revoke` | Token revocation (RFC 7009) |
| `GET` | `/api/v1/auth/jwks` | Public key set (RFC 7517) |
| `GET` | `/.well-known/agent-configuration` | Agent auth server metadata |

### Agent Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/agents` | Register new agent |
| `POST` | `/api/v1/agents/bootstrap` | Self-register a root agent |
| `GET` | `/api/v1/agents` | List agents (scoped to caller's subtree) |
| `GET` | `/api/v1/agents/{agent_id}` | Get agent details |
| `PATCH` | `/api/v1/agents/{agent_id}` | Update agent |
| `DELETE` | `/api/v1/agents/{agent_id}` | Deactivate agent |

### Credential Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/credentials` | Issue new API key (raw value returned once) |
| `GET` | `/api/v1/credentials` | List credentials (masked) |
| `POST` | `/api/v1/credentials/{cred_id}/rotate` | Rotate credential |
| `DELETE` | `/api/v1/credentials/{cred_id}` | Revoke credential |

### Policies & Scopes

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/policies` | Create policy |
| `GET` | `/api/v1/policies` | List policies |
| `POST` | `/api/v1/policies/evaluate` | Dry-run policy evaluation |
| `POST` | `/api/v1/scopes` | Register custom scope |
| `GET` | `/api/v1/scopes` | List scopes |

### Delegations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/delegations` | Create delegation |
| `GET` | `/api/v1/delegations` | List delegations |
| `GET` | `/api/v1/delegations/{id}/chain` | View full delegation chain |
| `DELETE` | `/api/v1/delegations/{id}` | Revoke delegation (cascading) |

### Observability

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/audit/events` | Query audit log |
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |

### Auth Grant Types

The `/auth/token` endpoint supports:

- **`client_credentials`** — Agent authenticates with its own API key or client secret
- **`agent_delegation`** — Agent presents a delegation token from its parent to get scoped access
- **`token_exchange`** (RFC 8693) — Exchange one token type for another with reduced scope
- **`refresh_token`** — Rotating refresh token flow with replay detection

---

## Identity Model

Every entity in the system — orchestrators, sub-agents, tool-calling workers — is an **Agent**. There is no separate "Owner" table. Hierarchy is expressed through self-referencing parent relationships and the Delegation table.

- A **root agent** (`parent_agent_id = null`, `trust_level = root`) is the trust anchor for its subtree
- Child agents are registered by their parent and inherit a subset of the parent's permissions
- Delegation chains are enforced: scopes can only be attenuated, never escalated

```
Root Agent
  └── Child Agent (orchestrator)
        └── Sub-Agent (tool worker)
              └── Ephemeral Agent (single-task)
```

---

## Security

- API keys stored as **argon2id hashes** — raw value shown once at creation, no recovery
- JWTs signed with **RS256** (RSA-2048) for external tokens
- Token **JTI blocklist** in Redis for revocation
- Refresh token **family tracking** — reuse of a revoked refresh token revokes the entire family
- **Scope attenuation** enforced on all delegations
- **Sliding window rate limiting** per agent via Redis
- Every credential operation produces an **immutable audit event**
- Audit table is append-only at the database role level

---

## Development

```bash
make help          # Show all available commands

make test          # Run full test suite
make test-unit     # Unit tests only
make test-integration  # Integration tests (requires docker compose up)

make lint          # Run ruff linter
make format        # Format code with ruff
make typecheck     # Run mypy type checker

make migrate                 # Apply pending migrations
make migrate-create          # Create a new migration (interactive)
```

### Project Structure

```
src/agentauth/
├── main.py              # FastAPI app factory
├── config.py            # Pydantic settings
├── dependencies.py      # FastAPI dependency injection
├── models/              # SQLAlchemy ORM models
├── schemas/             # Pydantic request/response schemas
├── api/v1/              # Route handlers
├── services/            # Business logic
├── core/                # Shared infrastructure (DB, Redis, security)
└── tasks/               # Celery async tasks (key rotation, webhooks)

tests/
├── unit/                # Isolated service/crypto tests
└── integration/         # Full API flow tests with real Postgres + Redis
```

---

## Implementation Status

### Phase 1 — Foundation
- [x] FastAPI app factory with health/readiness endpoints
- [x] SQLAlchemy 2.0 async engine + Alembic migrations
- [x] Agent model with self-referencing hierarchy
- [x] Root agent bootstrap registration
- [x] Credential issuance (API keys, argon2 hashing)
- [x] API key authentication middleware

### Phase 2 — Token Service
- [x] RSA + ECDSA key pair management (JWK)
- [x] JWT token minting with agent claims
- [x] `client_credentials` grant type
- [x] Token introspection (RFC 7662) with Redis caching
- [x] Token revocation (RFC 7009) with JTI blocklist
- [x] Rotating refresh tokens with replay detection

### Phase 3 — Authorization
- [x] Scope registry with hierarchical resolution
- [x] Policy model with CRUD endpoints
- [x] Policy evaluation engine (deny-override)
- [x] Authorization middleware
- [x] Delegation model with chain traversal
- [x] `agent_delegation` grant type

### Phase 4 — Observability & Hardening
- [x] Audit log query API
- [x] Sliding window rate limiting
- [x] Webhook delivery (Celery, HMAC-SHA256 signed)
- [x] Well-known discovery endpoint

### Phase 5 — Advanced (Planned)
- [ ] Agent attestation (TEE support)
- [ ] DID (Decentralized Identifier) support
- [ ] mTLS client certificates
- [ ] Multi-tenant / Organization support
- [ ] Agent-to-agent mutual authentication
- [ ] Dashboard UI
