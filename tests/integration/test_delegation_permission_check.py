"""Integration tests for check_permission honouring active delegations (Task 8.2)."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.services.authorization import AuthorizationService
from agentauth.services.delegation import DelegationService


@pytest.mark.asyncio
class TestCheckPermissionWithDelegations:
    """Tests that check_permission returns allowed=true for delegation-granted scopes."""

    async def test_delegation_allows_check_permission(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Agent B with agents.read delegation returns allowed=true for read on /api/v1/agents."""
        delegation_service = DelegationService(db_session)
        await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["agents.read"],
        )
        await db_session.commit()

        authz = AuthorizationService(db_session)
        result = await authz.evaluate(
            agent_id=child_agent.id,
            action="read",
            resource="/api/v1/agents",
        )
        assert result.allowed is True
        assert result.delegation_id is not None

    async def test_revoked_delegation_denies_check_permission(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """After delegation is revoked, check_permission returns allowed=false."""
        delegation_service = DelegationService(db_session)
        delegation = await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["agents.read"],
        )
        await db_session.commit()

        # First verify it's allowed
        authz = AuthorizationService(db_session)
        result = await authz.evaluate(
            agent_id=child_agent.id,
            action="read",
            resource="/api/v1/agents",
        )
        assert result.allowed is True

        # Revoke and verify it's denied
        await delegation_service.revoke_delegation(delegation.id, cascade=False)
        await db_session.commit()

        result2 = await authz.evaluate(
            agent_id=child_agent.id,
            action="read",
            resource="/api/v1/agents",
        )
        assert result2.allowed is False

    async def test_explicit_deny_overrides_delegation_allow(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """An explicit DENY policy must override a delegation-based allow."""
        from agentauth.models.policy import Policy, PolicyEffect

        # Grant delegation
        delegation_service = DelegationService(db_session)
        await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["agents.read"],
        )
        await db_session.commit()

        # Create explicit DENY policy for child_agent
        deny_policy = Policy(
            created_by_agent_id=root_agent.id,
            name="deny-agents-read",
            effect=PolicyEffect.DENY,
            subjects={"agent_ids": [str(child_agent.id)]},
            resources={"paths": ["/api/v1/agents"]},
            actions=["read"],
            conditions={},
            priority=100,
            enabled=True,
        )
        db_session.add(deny_policy)
        await db_session.commit()

        authz = AuthorizationService(db_session)
        result = await authz.evaluate(
            agent_id=child_agent.id,
            action="read",
            resource="/api/v1/agents",
        )
        assert result.allowed is False, "Explicit DENY must override delegation allow"

    async def test_delegation_id_in_response(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Response includes delegation_id when permission is granted via delegation."""
        delegation_service = DelegationService(db_session)
        delegation = await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["agents.read"],
        )
        await db_session.commit()

        authz = AuthorizationService(db_session)
        result = await authz.evaluate(
            agent_id=child_agent.id,
            action="read",
            resource="/api/v1/agents",
        )
        assert result.allowed is True
        assert result.delegation_id == delegation.id
