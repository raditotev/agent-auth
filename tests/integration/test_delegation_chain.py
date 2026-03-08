"""Integration tests for delegation chain traversal and scope attenuation."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus, AgentType, TrustLevel
from agentauth.models.credential import CredentialType
from agentauth.services.credential import CredentialService
from agentauth.services.delegation import DelegationService


@pytest.mark.asyncio
class TestDelegationChainTraversal:
    """Tests for get_delegation_chain and effective scopes."""

    async def test_get_delegation_chain_root_to_leaf(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Create delegation chain and traverse from leaf to root."""
        # Create a third agent (grandchild)
        grandchild = Agent(
            parent_agent_id=child_agent.id,
            name="test-grandchild-agent",
            agent_type=AgentType.TOOL,
            description="Test grandchild",
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=0,
            agent_metadata={"test": True},
        )
        db_session.add(grandchild)
        await db_session.commit()
        await db_session.refresh(grandchild)

        # Create credentials for auth
        credential_service = CredentialService(db_session)
        _, root_key = await credential_service.create_credential(
            agent_id=root_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["admin.full"],
        )
        _, child_key = await credential_service.create_credential(
            agent_id=child_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["api.read"],
        )
        _, grandchild_key = await credential_service.create_credential(
            agent_id=grandchild.id,
            credential_type=CredentialType.API_KEY,
            scopes=["api.read"],
        )
        await db_session.commit()

        # Root -> Child: scopes [api.read, api.write, files.read]
        # Child -> Grandchild: scopes [api.read] (attenuated)
        delegation_service = DelegationService(db_session)

        d1 = await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read", "api.write", "files.read"],
            max_chain_depth=3,
        )
        await db_session.commit()

        d2 = await delegation_service.create_delegation(
            delegator_agent_id=child_agent.id,
            delegate_agent_id=grandchild.id,
            scopes=["api.read"],
            max_chain_depth=2,
        )
        await db_session.commit()

        # Get chain from leaf delegation (d2)
        chain = await delegation_service.get_delegation_chain(d2.id)
        assert len(chain) == 2
        assert chain[0].id == d1.id
        assert chain[1].id == d2.id
        assert chain[0].delegator_agent_id == root_agent.id
        assert chain[0].delegate_agent_id == child_agent.id
        assert chain[1].delegator_agent_id == child_agent.id
        assert chain[1].delegate_agent_id == grandchild.id

        # Effective scopes = intersection
        scope_sets = [set(d.scopes) for d in chain]
        effective = scope_sets[0].intersection(*scope_sets[1:])
        assert effective == {"api.read"}

    async def test_get_delegation_chain_api(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Test GET /delegations/{id}/chain returns correct chain."""
        credential_service = CredentialService(db_session)
        _, root_key = await credential_service.create_credential(
            agent_id=root_agent.id,
            credential_type=CredentialType.API_KEY,
            scopes=["admin.full"],
        )
        await db_session.commit()

        delegation_service = DelegationService(db_session)
        delegation = await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read", "files.read"],
            max_chain_depth=3,
        )
        await db_session.commit()

        response = await client.get(
            f"/api/v1/delegations/{delegation.id}/chain",
            headers={"X-Agent-Key": root_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["delegation_id"] == str(delegation.id)
        assert len(data["chain"]) == 1
        assert data["chain"][0]["delegator_agent_id"] == str(root_agent.id)
        assert data["chain"][0]["delegate_agent_id"] == str(child_agent.id)
        assert set(data["effective_scopes"]) == {"api.read", "files.read"}

    async def test_get_effective_scopes_root_agent(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
    ) -> None:
        """Root agent (no incoming delegation) has unrestricted scopes."""
        delegation_service = DelegationService(db_session)
        scopes, depth = await delegation_service.get_effective_scopes_and_depth(root_agent.id)
        assert scopes is None
        assert depth == 0

    async def test_get_effective_scopes_delegated_agent(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Delegated agent has effective scopes from incoming delegation."""
        delegation_service = DelegationService(db_session)
        await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read", "files.read"],
            max_chain_depth=3,
        )
        await db_session.commit()

        scopes, depth = await delegation_service.get_effective_scopes_and_depth(child_agent.id)
        assert scopes is not None
        assert set(scopes) == {"api.read", "files.read"}
        assert depth == 1

    async def test_scope_attenuation_prevents_escalation(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Delegation cannot grant scopes delegator does not hold."""
        delegation_service = DelegationService(db_session)
        # Child has no incoming delegation, so effective_scopes is None (root-like)
        # Actually child has parent_agent_id but no Delegation record - get_effective_scopes
        # looks at Delegation table, not parent_agent_id. So child with no incoming
        # delegation is treated as root -> unrestricted.
        # To test attenuation we need: root -> child (with scopes), then child -> grandchild
        # with MORE scopes should fail.
        grandchild = Agent(
            parent_agent_id=child_agent.id,
            name="grandchild",
            agent_type=AgentType.TOOL,
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=0,
        )
        db_session.add(grandchild)
        await db_session.commit()
        await db_session.refresh(grandchild)

        # Root -> Child with limited scopes
        await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read"],
            max_chain_depth=3,
        )
        await db_session.commit()

        # Child -> Grandchild with escalated scope (api.write) should fail
        with pytest.raises(ValueError, match="Scope escalation"):
            await delegation_service.create_delegation(
                delegator_agent_id=child_agent.id,
                delegate_agent_id=grandchild.id,
                scopes=["api.read", "api.write"],
                max_chain_depth=2,
            )

    async def test_chain_depth_limit(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Creating delegation beyond max_chain_depth fails."""
        grandchild = Agent(
            parent_agent_id=child_agent.id,
            name="grandchild",
            agent_type=AgentType.TOOL,
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=0,
        )
        db_session.add(grandchild)
        await db_session.commit()
        await db_session.refresh(grandchild)

        great_grandchild = Agent(
            parent_agent_id=grandchild.id,
            name="great-grandchild",
            agent_type=AgentType.TOOL,
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=0,
        )
        db_session.add(great_grandchild)
        await db_session.commit()
        await db_session.refresh(great_grandchild)

        delegation_service = DelegationService(db_session)

        # Root -> Child
        await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read"],
            max_chain_depth=2,
        )
        await db_session.commit()

        # Child -> Grandchild
        await delegation_service.create_delegation(
            delegator_agent_id=child_agent.id,
            delegate_agent_id=grandchild.id,
            scopes=["api.read"],
            max_chain_depth=2,
        )
        await db_session.commit()

        # Grandchild -> Great-grandchild should fail (depth would be 3, max is 2)
        with pytest.raises(ValueError, match="Chain depth.*exceeds maximum"):
            await delegation_service.create_delegation(
                delegator_agent_id=grandchild.id,
                delegate_agent_id=great_grandchild.id,
                scopes=["api.read"],
                max_chain_depth=2,
            )

    async def test_cascade_revoke(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ) -> None:
        """Revoking root delegation cascades to downstream delegations."""
        grandchild = Agent(
            parent_agent_id=child_agent.id,
            name="grandchild",
            agent_type=AgentType.TOOL,
            trust_level=TrustLevel.DELEGATED,
            status=AgentStatus.ACTIVE,
            max_child_depth=0,
        )
        db_session.add(grandchild)
        await db_session.commit()
        await db_session.refresh(grandchild)

        delegation_service = DelegationService(db_session)

        d1 = await delegation_service.create_delegation(
            delegator_agent_id=root_agent.id,
            delegate_agent_id=child_agent.id,
            scopes=["api.read"],
            max_chain_depth=3,
        )
        await db_session.commit()

        d2 = await delegation_service.create_delegation(
            delegator_agent_id=child_agent.id,
            delegate_agent_id=grandchild.id,
            scopes=["api.read"],
            max_chain_depth=2,
        )
        await db_session.commit()

        # Revoke root delegation with cascade
        revoked_count = await delegation_service.revoke_delegation(d1.id, cascade=True)
        assert revoked_count == 2

        await db_session.refresh(d1)
        await db_session.refresh(d2)
        assert d1.revoked_at is not None
        assert d2.revoked_at is not None
