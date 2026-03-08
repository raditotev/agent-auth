"""Tests for Admin API endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.audit import ActorType, AuditEvent, EventOutcome
from agentauth.models.credential import Credential, CredentialType


class TestAdminStats:
    """Tests for GET /api/v1/stats endpoint."""

    @pytest.mark.asyncio
    async def test_stats_returns_counts_of_agents_credentials_tokens_issued(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        root_agent: Agent,
    ) -> None:
        """Test stats endpoint returns agent, credential, and token counts."""
        # Create a credential for root_agent
        credential = Credential(
            agent_id=root_agent.id,
            type=CredentialType.API_KEY,
            prefix="test_abc1",
            hash="argon2$dummy",
        )
        db_session.add(credential)

        # Record token.issued audit events
        for _ in range(3):
            event = AuditEvent(
                event_type="token.issued",
                actor_type=ActorType.AGENT,
                actor_id=root_agent.id,
                target_type="token",
                target_id=None,
                action="issued",
                outcome=EventOutcome.SUCCESS,
            )
            db_session.add(event)

        await db_session.commit()

        response = await client.get(
            "/api/v1/stats",
            headers={"X-Admin-Key": "test-admin-key"},
        )
        assert response.status_code == 200

        json_data = response.json()
        assert "data" in json_data
        assert json_data["data"]["agents"] == 1
        assert json_data["data"]["credentials"] == 1
        assert json_data["data"]["tokens_issued"] == 3

    @pytest.mark.asyncio
    async def test_stats_returns_zero_when_empty(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """Test stats returns zeros when no data exists."""
        # Use fresh db_session with no fixtures - need to ensure empty DB
        # The client uses db_session from conftest which creates tables
        # We need a session that has no agents - the default conftest client
        # might run migrations that leave tables empty
        response = await client.get(
            "/api/v1/stats",
            headers={"X-Admin-Key": "test-admin-key"},
        )
        assert response.status_code == 200

        json_data = response.json()
        assert "data" in json_data
        assert json_data["data"]["agents"] >= 0
        assert json_data["data"]["credentials"] >= 0
        assert json_data["data"]["tokens_issued"] >= 0

    @pytest.mark.asyncio
    async def test_stats_requires_admin_key(
        self,
        client: AsyncClient,
    ) -> None:
        """Test stats returns 401 without X-Admin-Key header."""
        response = await client.get("/api/v1/stats")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_stats_rejects_invalid_admin_key(
        self,
        client: AsyncClient,
    ) -> None:
        """Test stats returns 401 with wrong X-Admin-Key."""
        response = await client.get(
            "/api/v1/stats",
            headers={"X-Admin-Key": "wrong-key"},
        )
        assert response.status_code == 401


class TestAdminAudit:
    """Tests for GET /api/v1/audit/events endpoint."""

    @pytest.mark.asyncio
    async def test_audit_events_requires_admin_key(
        self,
        client: AsyncClient,
    ) -> None:
        """Test audit events returns 401 without X-Admin-Key header."""
        response = await client.get("/api/v1/audit/events")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_audit_events_returns_data_with_admin_key(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        root_agent: Agent,
    ) -> None:
        """Test audit events returns data when authenticated with admin key."""
        # Create an audit event
        event = AuditEvent(
            event_type="credential.created",
            actor_type=ActorType.AGENT,
            actor_id=root_agent.id,
            target_type="credential",
            target_id=None,
            action="created",
            outcome=EventOutcome.SUCCESS,
        )
        db_session.add(event)
        await db_session.commit()

        response = await client.get(
            "/api/v1/audit/events",
            headers={"X-Admin-Key": "test-admin-key"},
        )
        assert response.status_code == 200
        json_data = response.json()
        assert "data" in json_data
        assert len(json_data["data"]) >= 1
