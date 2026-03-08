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