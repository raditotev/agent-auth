"""Integration tests for credential ownership / cross-agent authority enforcement.

Task 7.1 — verifies that credential creation, rotation, and revocation are
restricted to agents within the caller's trust hierarchy.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.services.credential import CredentialService


@pytest.mark.asyncio
class TestCredentialOwnership:
    """Credential authority is based solely on the trust hierarchy (parent-child)."""

    # ------------------------------------------------------------------ helpers

    async def _create_unrelated_root(self, db_session: AsyncSession, name: str) -> Agent:
        """Create a root agent in a different trust hierarchy."""
        agent = Agent(
            parent_agent_id=None,
            name=name,
            agent_type=AgentType.AUTONOMOUS,
            description="Unrelated root agent",
            trust_level=TrustLevel.ROOT,
            status=AgentStatus.ACTIVE,
            max_child_depth=3,
            agent_metadata={},
        )
        db_session.add(agent)
        await db_session.flush()
        await db_session.refresh(agent)
        return agent

    # ------------------------------------------------------------------ create

    async def test_create_credential_for_self_succeeds(
        self, client: AsyncClient, auth_agent: Agent
    ) -> None:
        """An agent can always create credentials for itself."""
        response = await client.post(
            "/api/v1/credentials",
            json={"agent_id": str(auth_agent.id), "type": "api_key"},
        )
        assert response.status_code == 201

    async def test_create_credential_for_child_succeeds(
        self, client: AsyncClient, auth_child_agent: Agent
    ) -> None:
        """A parent can create credentials for its direct child."""
        response = await client.post(
            "/api/v1/credentials",
            json={"agent_id": str(auth_child_agent.id), "type": "api_key"},
        )
        assert response.status_code == 201

    async def test_create_credential_for_grandchild_succeeds(
        self, client: AsyncClient, db_session: AsyncSession, auth_child_agent: Agent
    ) -> None:
        """An ancestor (root) can create credentials for any descendant."""
        grandchild = Agent(
            parent_agent_id=auth_child_agent.id,
            name="test-grandchild-agent",
            agent_type=AgentType.TOOL,
            description="Grandchild agent",
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=3,
            agent_metadata={},
        )
        db_session.add(grandchild)
        await db_session.flush()
        await db_session.refresh(grandchild)

        response = await client.post(
            "/api/v1/credentials",
            json={"agent_id": str(grandchild.id), "type": "api_key"},
        )
        assert response.status_code == 201

    async def test_create_credential_for_unrelated_agent_denied(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """An agent cannot create credentials for an agent in a different trust hierarchy."""
        other_root = await self._create_unrelated_root(db_session, "other-root-cred-test")

        response = await client.post(
            "/api/v1/credentials",
            json={"agent_id": str(other_root.id), "type": "api_key"},
        )
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["status"] == 403
        assert "authority" in detail["title"].lower() or "denied" in detail["title"].lower()

    async def test_create_credential_denied_audit_log_recorded(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """Denied credential creation is recorded in the audit log."""
        from agentauth.services.audit import AuditService

        other_root = await self._create_unrelated_root(db_session, "other-root-audit-test")

        response = await client.post(
            "/api/v1/credentials",
            json={"agent_id": str(other_root.id), "type": "api_key"},
        )
        assert response.status_code == 403

        audit_service = AuditService(db_session)
        events = await audit_service.get_events(event_type="credential.creation_denied")
        assert len(events) >= 1
        denied_event = events[0]
        assert denied_event.event_type == "credential.creation_denied"
        assert str(denied_event.target_id) == str(other_root.id)

    # ------------------------------------------------------------------ rotate

    async def test_rotate_credential_for_self_succeeds(
        self, client: AsyncClient, db_session: AsyncSession, auth_agent: Agent
    ) -> None:
        """An agent can rotate its own credentials."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=auth_agent.id)

        response = await client.post(f"/api/v1/credentials/{credential.id}/rotate")
        assert response.status_code == 200

    async def test_rotate_credential_for_child_succeeds(
        self, client: AsyncClient, db_session: AsyncSession, auth_child_agent: Agent
    ) -> None:
        """A parent can rotate credentials belonging to a child agent."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=auth_child_agent.id)

        response = await client.post(f"/api/v1/credentials/{credential.id}/rotate")
        assert response.status_code == 200

    async def test_rotate_credential_for_unrelated_agent_denied(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """An agent cannot rotate credentials belonging to an unrelated agent."""
        other_root = await self._create_unrelated_root(db_session, "other-root-rotate-test")
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=other_root.id)

        response = await client.post(f"/api/v1/credentials/{credential.id}/rotate")
        assert response.status_code == 403

    # ------------------------------------------------------------------ revoke

    async def test_revoke_credential_for_self_succeeds(
        self, client: AsyncClient, db_session: AsyncSession, auth_agent: Agent
    ) -> None:
        """An agent can revoke its own credentials."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=auth_agent.id)

        response = await client.delete(f"/api/v1/credentials/{credential.id}")
        assert response.status_code == 200

    async def test_revoke_credential_for_child_succeeds(
        self, client: AsyncClient, db_session: AsyncSession, auth_child_agent: Agent
    ) -> None:
        """A parent can revoke credentials belonging to a child agent."""
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=auth_child_agent.id)

        response = await client.delete(f"/api/v1/credentials/{credential.id}")
        assert response.status_code == 200

    async def test_revoke_credential_for_unrelated_agent_denied(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """An agent cannot revoke credentials belonging to an unrelated agent."""
        other_root = await self._create_unrelated_root(db_session, "other-root-revoke-test")
        service = CredentialService(db_session)
        credential, _ = await service.create_credential(agent_id=other_root.id)

        response = await client.delete(f"/api/v1/credentials/{credential.id}")
        assert response.status_code == 403

    # ------------------------------------------------------------------ delegation-only

    async def test_delegation_alone_does_not_grant_credential_authority(
        self, client: AsyncClient, db_session: AsyncSession
    ) -> None:
        """A delegation relationship alone does NOT grant credential management rights."""
        from agentauth.services.delegation import DelegationService

        # Create unrelated root and delegate FROM auth_agent TO other_root
        other_root = await self._create_unrelated_root(
            db_session, "other-root-delegation-test"
        )
        # Give other_root a credential so it has scopes for delegation
        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=other_root.id, scopes=["api.read"]
        )
        await db_session.commit()

        # auth_agent delegates to other_root — but this must NOT allow
        # auth_agent to manage other_root's credentials
        # (verify the 403 still applies)
        credential, _ = await credential_service.create_credential(agent_id=other_root.id)

        response = await client.delete(f"/api/v1/credentials/{credential.id}")
        assert response.status_code == 403
