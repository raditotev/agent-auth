"""Unit tests for circular and self-delegation prevention."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from agentauth.core.exceptions import ValidationError
from agentauth.services.delegation import DelegationService


def _make_agent(agent_id=None, active=True):
    """Create a lightweight agent-like namespace."""
    agent = SimpleNamespace()
    agent.id = agent_id or uuid4()
    agent.is_active = lambda: active
    return agent


class TestSelfDelegation:
    """Self-delegation (A→A) must be rejected."""

    @pytest.mark.asyncio
    async def test_self_delegation_raises_validation_error(self) -> None:
        """An agent cannot delegate to itself."""
        mock_session = AsyncMock()
        service = DelegationService(mock_session)
        agent_id = uuid4()

        with pytest.raises(ValidationError, match="cannot delegate to itself"):
            await service.create_delegation(
                delegator_agent_id=agent_id,
                delegate_agent_id=agent_id,
                scopes=["read"],
            )

        # Session should not have been touched
        mock_session.execute.assert_not_called()


class TestDirectCircularDelegation:
    """Direct circular delegation (A→B when B→A exists) must be rejected."""

    @pytest.mark.asyncio
    async def test_direct_circular_raises_validation_error(self) -> None:
        """
        A→B is rejected when B→A already exists.

        Existing graph: B delegated to A (delegator=B, delegate=A).
        Attempting: A delegates to B (delegator=A, delegate=B).
        BFS forward from delegate B: B delegated to A? Yes (the existing one).
        Wait — BFS from B finds B's delegates. If B→A exists, then A is a
        child of B. But we're checking if delegator (A) is reachable from
        delegate (B). B delegated to A → A is reachable. A == delegator. Cycle!
        """
        agent_a_id = uuid4()
        agent_b_id = uuid4()

        mock_session = AsyncMock()

        # execute call 1: load delegator (agent_a)
        result_delegator = MagicMock()
        result_delegator.scalar_one_or_none.return_value = _make_agent(agent_a_id)

        # execute call 2: load delegate (agent_b)
        result_delegate = MagicMock()
        result_delegate.scalar_one_or_none.return_value = _make_agent(agent_b_id)

        # execute call 3: cycle detection — BFS forward from delegate (B).
        # Query: who did B delegate to? → A (B→A exists).
        # A == delegator_agent_id → cycle detected.
        result_cycle = MagicMock()
        result_cycle.fetchall.return_value = [(agent_a_id,)]

        mock_session.execute = AsyncMock(
            side_effect=[result_delegator, result_delegate, result_cycle]
        )

        service = DelegationService(mock_session)
        with pytest.raises(ValidationError, match="Circular delegation chain detected"):
            await service.create_delegation(
                delegator_agent_id=agent_a_id,
                delegate_agent_id=agent_b_id,
                scopes=["read"],
            )


class TestIndirectCircularDelegation:
    """Indirect circular delegation (A→B→C, then C→A) must be rejected."""

    @pytest.mark.asyncio
    async def test_indirect_circular_raises_validation_error(self) -> None:
        """
        Given chain A→B→C, creating C→A is rejected.

        Existing: A delegates to B (delegator=A, delegate=B),
                  B delegates to C (delegator=B, delegate=C).
        Attempting: C delegates to A (delegator=C, delegate=A).

        BFS forward from delegate (A):
          - Level 1: A delegated to B → {B}. B != C (delegator). Continue.
          - Level 2: B delegated to C → {C}. C == delegator. Cycle!
        """
        agent_a_id = uuid4()
        agent_b_id = uuid4()
        agent_c_id = uuid4()

        mock_session = AsyncMock()

        # execute call 1: load delegator (agent_c)
        result_delegator = MagicMock()
        result_delegator.scalar_one_or_none.return_value = _make_agent(agent_c_id)

        # execute call 2: load delegate (agent_a)
        result_delegate = MagicMock()
        result_delegate.scalar_one_or_none.return_value = _make_agent(agent_a_id)

        # execute call 3: BFS level 1 — who did A delegate to? → B
        result_level1 = MagicMock()
        result_level1.fetchall.return_value = [(agent_b_id,)]

        # execute call 4: BFS level 2 — who did B delegate to? → C
        # C == delegator_agent_id → cycle detected
        result_level2 = MagicMock()
        result_level2.fetchall.return_value = [(agent_c_id,)]

        mock_session.execute = AsyncMock(
            side_effect=[result_delegator, result_delegate, result_level1, result_level2]
        )

        service = DelegationService(mock_session)
        with pytest.raises(ValidationError, match="Circular delegation chain detected"):
            await service.create_delegation(
                delegator_agent_id=agent_c_id,
                delegate_agent_id=agent_a_id,
                scopes=["read"],
            )


class TestValidNonCircularDelegation:
    """Valid non-circular delegations still work."""

    @pytest.mark.asyncio
    async def test_valid_delegation_succeeds(self) -> None:
        """A→B succeeds when no cycle exists."""
        agent_a_id = uuid4()
        agent_b_id = uuid4()

        mock_session = AsyncMock()

        # execute call 1: load delegator (agent_a)
        result_delegator = MagicMock()
        result_delegator.scalar_one_or_none.return_value = _make_agent(agent_a_id)

        # execute call 2: load delegate (agent_b)
        result_delegate = MagicMock()
        result_delegate.scalar_one_or_none.return_value = _make_agent(agent_b_id)

        # execute call 3: cycle detection — BFS from B: B has no delegates
        result_no_cycle = MagicMock()
        result_no_cycle.fetchall.return_value = []

        # execute call 4: get_effective_scopes_and_depth for delegator (A)
        # No incoming delegations → root agent (None, 0)
        result_scopes = MagicMock()
        result_scopes.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[result_delegator, result_delegate, result_no_cycle, result_scopes]
        )
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        service = DelegationService(mock_session)
        result = await service.create_delegation(
            delegator_agent_id=agent_a_id,
            delegate_agent_id=agent_b_id,
            scopes=["read"],
        )

        assert result is not None
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
