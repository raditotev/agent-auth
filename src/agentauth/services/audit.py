"""Audit service for recording security events."""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.audit import ActorType, AuditEvent, EventOutcome

logger = structlog.get_logger()


class AuditService:
    """Service for recording and querying audit events."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize audit service."""
        self.session = session

    async def record_event(
        self,
        event_type: str,
        action: str,
        outcome: EventOutcome,
        actor_type: ActorType,
        target_type: str,
        actor_id: UUID | None = None,
        target_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Record an audit event.

        Args:
            event_type: Type of event (e.g., "credential.created")
            action: Action performed (e.g., "created", "revoked")
            outcome: Event outcome (success, failure, denied)
            actor_type: Type of actor (agent or system)
            target_type: Type of resource (credential, agent, etc.)
            actor_id: UUID of actor (agent), null for system
            target_id: UUID of target resource
            metadata: Additional event metadata

        Returns:
            Created AuditEvent
        """
        event = AuditEvent(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            target_type=target_type,
            target_id=target_id,
            action=action,
            outcome=outcome,
            event_metadata=metadata or {},
        )

        self.session.add(event)
        await self.session.flush()

        logger.info(
            "audit_event_recorded",
            event_type=event_type,
            action=action,
            outcome=outcome.value,
            actor_type=actor_type.value,
            actor_id=str(actor_id) if actor_id else None,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
        )

        return event

    async def record_credential_created(
        self,
        credential_id: UUID,
        agent_id: UUID,
        credential_type: str,
        actor_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record credential creation event."""
        return await self.record_event(
            event_type="credential.created",
            action="created",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT if actor_id else ActorType.SYSTEM,
            target_type="credential",
            actor_id=actor_id,
            target_id=credential_id,
            metadata={
                **(metadata or {}),
                "agent_id": str(agent_id),
                "credential_type": credential_type,
            },
        )

    async def record_credential_revoked(
        self,
        credential_id: UUID,
        agent_id: UUID,
        actor_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record credential revocation event."""
        return await self.record_event(
            event_type="credential.revoked",
            action="revoked",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT if actor_id else ActorType.SYSTEM,
            target_type="credential",
            actor_id=actor_id,
            target_id=credential_id,
            metadata={
                **(metadata or {}),
                "agent_id": str(agent_id),
            },
        )

    async def record_credential_rotated(
        self,
        old_credential_id: UUID,
        new_credential_id: UUID,
        agent_id: UUID,
        actor_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record credential rotation event."""
        return await self.record_event(
            event_type="credential.rotated",
            action="rotated",
            outcome=EventOutcome.SUCCESS,
            actor_type=ActorType.AGENT if actor_id else ActorType.SYSTEM,
            target_type="credential",
            actor_id=actor_id,
            target_id=new_credential_id,
            metadata={
                **(metadata or {}),
                "agent_id": str(agent_id),
                "old_credential_id": str(old_credential_id),
                "new_credential_id": str(new_credential_id),
            },
        )

    async def get_events(
        self,
        event_type: str | None = None,
        actor_id: UUID | None = None,
        target_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """
        Query audit events.

        Args:
            event_type: Filter by event type
            actor_id: Filter by actor ID
            target_id: Filter by target ID
            limit: Maximum number of events to return
            offset: Offset for pagination

        Returns:
            List of matching audit events
        """
        query = select(AuditEvent)

        if event_type:
            query = query.where(AuditEvent.event_type == event_type)
        if actor_id:
            query = query.where(AuditEvent.actor_id == actor_id)
        if target_id:
            query = query.where(AuditEvent.target_id == target_id)

        query = query.order_by(AuditEvent.created_at.desc())
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())
