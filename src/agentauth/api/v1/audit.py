"""Audit log query API (Task 4.3)."""

import json
from datetime import datetime
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.database import get_session
from agentauth.models.audit import AuditEvent, EventOutcome

logger = structlog.get_logger()

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events")
async def list_audit_events(
    session: Annotated[AsyncSession, Depends(get_session)],
    event_type: str | None = Query(None, description="Filter by event type"),
    actor_id: UUID | None = Query(None, description="Filter by actor agent ID"),
    target_id: UUID | None = Query(None, description="Filter by target resource ID"),
    outcome: EventOutcome | None = Query(None, description="Filter by outcome"),
    from_date: datetime | None = Query(None, description="Start of date range (ISO 8601)"),
    to_date: datetime | None = Query(None, description="End of date range (ISO 8601)"),
    after: UUID | None = Query(None, description="Cursor: return events after this ID"),
    limit: int = Query(50, ge=1, le=500, description="Page size"),
    export: bool = Query(False, description="Export as JSONL instead of JSON"),
) -> Response:
    """
    Query the audit event log with flexible filters and cursor-based pagination.

    Use `after` (an event ID) as a cursor for the next page.
    Set `export=true` to receive newline-delimited JSON (JSONL) for bulk export.
    """
    query = select(AuditEvent).order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())

    if event_type:
        query = query.where(AuditEvent.event_type == event_type)
    if actor_id:
        query = query.where(AuditEvent.actor_id == actor_id)
    if target_id:
        query = query.where(AuditEvent.target_id == target_id)
    if outcome:
        query = query.where(AuditEvent.outcome == outcome)
    if from_date:
        query = query.where(AuditEvent.created_at >= from_date)
    if to_date:
        query = query.where(AuditEvent.created_at <= to_date)
    if after:
        # Cursor-based pagination: events after the given ID (by insertion order)
        cursor_result = await session.execute(
            select(AuditEvent.created_at).where(AuditEvent.id == after)
        )
        cursor_ts = cursor_result.scalar_one_or_none()
        if cursor_ts:
            query = query.where(AuditEvent.created_at > cursor_ts)

    query = query.limit(limit)
    result = await session.execute(query)
    events = list(result.scalars().all())

    def event_to_dict(e: AuditEvent) -> dict:
        return {
            "id": str(e.id),
            "event_type": e.event_type,
            "actor_type": e.actor_type.value,
            "actor_id": str(e.actor_id) if e.actor_id else None,
            "target_type": e.target_type,
            "target_id": str(e.target_id) if e.target_id else None,
            "action": e.action,
            "outcome": e.outcome.value,
            "metadata": e.event_metadata,
            "created_at": e.created_at.isoformat(),
        }

    next_cursor = str(events[-1].id) if len(events) == limit else None

    if export:
        jsonl_body = "\n".join(json.dumps(event_to_dict(e)) for e in events)
        return Response(
            content=jsonl_body,
            media_type="application/x-ndjson",
            headers={
                "X-Next-Cursor": next_cursor or "",
                "X-Total-Returned": str(len(events)),
            },
        )

    body = {
        "data": [event_to_dict(e) for e in events],
        "meta": {
            "returned": len(events),
            "limit": limit,
            "next_cursor": next_cursor,
        },
    }
    return Response(
        content=json.dumps(body),
        media_type="application/json",
        headers={"X-Next-Cursor": next_cursor or ""},
    )
