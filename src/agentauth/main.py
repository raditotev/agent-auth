"""FastAPI application factory for AgentAuth."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agentauth.api.middleware import AuthenticationMiddleware, AuthorizationMiddleware, RateLimitMiddleware
from agentauth.api.v1 import api_router
from agentauth.api.v1.wellknown import router as wellknown_router
from agentauth.config import settings
from agentauth.core.database import close_db, init_db

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifecycle (startup and shutdown)."""
    logger.info("AgentAuth starting up")
    await init_db()
    yield
    logger.info("AgentAuth shutting down")
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AgentAuth",
        description="Identity and authentication service for AI agents",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Add middleware (LIFO order: last added runs first)
    # Execution order: AuthenticationMiddleware → AuthorizationMiddleware → RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthorizationMiddleware)
    app.add_middleware(AuthenticationMiddleware)

    # Include API v1 routes
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    # Well-known discovery endpoint (at root, not under /api/v1)
    app.include_router(wellknown_router)

    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health() -> JSONResponse:
        """Health check endpoint - returns 200 if service is running."""
        return JSONResponse(
            status_code=200,
            content={
                "status": "healthy",
                "service": "agentauth",
            },
        )

    # Readiness check endpoint
    @app.get("/ready", tags=["health"])
    async def ready() -> JSONResponse:
        """Readiness check endpoint - returns 200 if service is ready to accept traffic."""
        # TODO: Check database connection, Redis, etc.
        return JSONResponse(
            status_code=200,
            content={
                "status": "ready",
                "service": "agentauth",
            },
        )

    return app


app = create_app()
