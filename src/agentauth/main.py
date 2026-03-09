"""FastAPI application factory for AgentAuth."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from agentauth.api.middleware import (
    AuthenticationMiddleware,
    AuthorizationMiddleware,
    RateLimitMiddleware,
)
from agentauth.api.v1 import api_router
from agentauth.api.v1.wellknown import router as wellknown_router
from agentauth.config import settings
from agentauth.core.database import close_db, get_session_maker, init_db
from agentauth.core.redis import get_redis_client

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifecycle (startup and shutdown)."""
    logger.info("AgentAuth starting up")

    # Validate configuration — refuse to start in production with insecure defaults
    warnings = settings.validate_production_settings()
    for w in warnings:
        logger.warning("insecure_default_detected", message=w)

    await init_db()

    # Initialize Redis connection
    redis_client = get_redis_client()
    await redis_client.connect()

    # Seed default scopes and ensure signing keys exist
    from agentauth.services.crypto import CryptoService
    from agentauth.services.scope import ScopeService

    session_maker = get_session_maker()
    async with session_maker() as session:
        await ScopeService(session).seed_default_scopes()
        await CryptoService(session).rotate_keys()
        await session.commit()

    yield

    logger.info("AgentAuth shutting down")
    await close_db()
    await redis_client.disconnect()


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
        """Readiness check endpoint - returns 200 if all dependencies are reachable."""
        from sqlalchemy import text

        checks: dict[str, str] = {}
        overall_ok = True

        # Check database
        try:
            session_maker = get_session_maker()
            async with session_maker() as session:
                await session.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = f"error: {e}"
            overall_ok = False

        # Check Redis
        try:
            redis = get_redis_client()
            await redis.set("health:ready", "1", ex=10)
            checks["redis"] = "ok"
        except Exception as e:
            checks["redis"] = f"error: {e}"
            overall_ok = False

        return JSONResponse(
            status_code=200 if overall_ok else 503,
            content={
                "status": "ready" if overall_ok else "not_ready",
                "service": "agentauth",
                "checks": checks,
            },
        )

    return app


app = create_app()
