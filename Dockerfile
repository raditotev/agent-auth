FROM python:3.13-slim AS base

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# uv cache in /tmp so it's writable by any user
ENV UV_CACHE_DIR=/tmp/.cache/uv

# Install dependencies first (layer caching)
COPY pyproject.toml uv.lock ./
COPY mcp-server/pyproject.toml mcp-server/
RUN uv sync --frozen --no-dev --no-install-project --no-install-workspace

# Copy application code
COPY README.md ./
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY src/ ./src/
COPY mcp-server/src/ ./mcp-server/src/
COPY mcp-server/README.md ./mcp-server/

# Install the project and workspace members
RUN uv sync --frozen --no-dev

# Run as non-root user
RUN chown -R nobody:nogroup /tmp/.cache/uv /app
USER nobody

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "agentauth.main:app", "--host", "0.0.0.0", "--port", "8000"]
