"""Database configuration and session management."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import structlog
from sqlalchemy import TIMESTAMP, MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from uuid_extensions.uuid7 import uuid7

from agentauth.config import settings
from agentauth.core.url_utils import mask_url as _mask_url

logger = structlog.get_logger()

# SQLAlchemy naming convention for constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=convention)


class BaseModel(DeclarativeBase):
    """Base model class with common fields."""

    metadata = metadata

    # UUID7 primary key (time-sortable)
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid7,
        index=True,
    )

    # Timestamps (always UTC, timezone-aware)
    # Use TIMESTAMP WITH TIME ZONE in PostgreSQL to store timezone info
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


# Global engine and session maker
engine: AsyncEngine | None = None
async_session_maker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Get or create the database engine."""
    global engine
    if engine is None:
        engine = create_async_engine(
            str(settings.database_url),
            echo=settings.debug,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
        )
        logger.info("Database engine created", url=_mask_url(str(settings.database_url)))
    return engine


def get_session_maker() -> async_sessionmaker[AsyncSession]:
    """Get or create the async session maker."""
    global async_session_maker
    if async_session_maker is None:
        async_session_maker = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
        logger.info("Session maker created")
    return async_session_maker


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting async database sessions."""
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database connection."""
    get_engine()
    get_session_maker()
    logger.info("Database initialized")


async def close_db() -> None:
    """Close database connections."""
    global engine, async_session_maker
    if engine is not None:
        await engine.dispose()
        engine = None
        async_session_maker = None
        logger.info("Database connections closed")


# Type alias for dependency injection
DbSession = Annotated[AsyncSession, "database session"]
