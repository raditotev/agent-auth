FROM python:3.13-slim AS base

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# uv cache in /tmp so it's writable by any user
ENV UV_CACHE_DIR=/tmp/.cache/uv

# Install dependencies first (layer caching)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code
COPY README.md ./
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY src/ ./src/

# Install the project itself
RUN uv sync --frozen --no-dev

# Run as non-root user
RUN chown -R nobody:nogroup /tmp/.cache/uv /app
USER nobody

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "agentauth.main:app", "--host", "0.0.0.0", "--port", "8000"]
