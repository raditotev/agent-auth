"""Admin API endpoints — for platform operators only (X-Admin-Key)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.dependencies import require_admin_key
from agentauth.models.agent import Agent
from agentauth.models.audit import AuditEvent
from agentauth.models.credential import Credential
from agentauth.schemas.admin import StatsData, StatsResponse

router = APIRouter(tags=["admin"])


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Get system statistics",
    description="Returns counts of agents, credentials, and tokens issued. "
    "Requires X-Admin-Key header (platform operators only).",
)
async def get_stats(
    _: Annotated[None, Depends(require_admin_key)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> StatsResponse:
    """
    Return aggregate counts for admin dashboards and monitoring.

    - agents: Total number of registered agents
    - credentials: Total number of credentials (API keys, client secrets, etc.)
    - tokens_issued: Count of token.issued audit events (tokens minted)
    """
    agents_result = await session.execute(select(func.count()).select_from(Agent))
    agents_count = agents_result.scalar_one() or 0

    credentials_result = await session.execute(
        select(func.count()).select_from(Credential)
    )
    credentials_count = credentials_result.scalar_one() or 0

    tokens_result = await session.execute(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.event_type == "token.issued")
    )
    tokens_issued_count = tokens_result.scalar_one() or 0

    return StatsResponse(
        data=StatsData(
            agents=agents_count,
            credentials=credentials_count,
            tokens_issued=tokens_issued_count,
        ),
        meta={},
    )
