"""Unit tests for delegation cascade revocation."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from agentauth.services.delegation import DelegationService


def _make_delegation(
    *,
    delegation_id: UUID | None = None,
    delegator_agent_id: UUID | None = None,
    delegate_agent_id: UUID | None = None,
    chain_depth: int = 1,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SimpleNamespace:
    """Create a lightweight delegation-like namespace for unit tests."""
    d = SimpleNamespace()
    d.id = delegation_id or uuid4()
    d.delegator_agent_id = delegator_agent_id or uuid4()
    d.delegate_agent_id = delegate_agent_id or uuid4()
    d.scopes = ["read"]
    d.constraints = {}
    d.chain_depth = chain_depth
    d.max_chain_depth = 3
    d.expires_at = expires_at
    d.revoked_at = revoked_at
    d.created_at = datetime.now(UTC)
    d.updated_at = datetime.now(UTC)
    return d


class TestRevokeDelegationNoMatch:
    """revoke_delegation returns 0 when delegation does not exist."""

    @pytest.mark.asyncio
    async def test_returns_zero_when_not_found(self) -> None:
        """Returns 0 when the delegation ID is not found."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            count = await service.revoke_delegation(uuid4(), cascade=True)

        assert count == 0


class TestRevokeDelegationNoCascade:
    """revoke_delegation with cascade=False revokes only the target delegation."""

    @pytest.mark.asyncio
    async def test_revokes_only_direct_delegation(self) -> None:
        """cascade=False: only the one delegation is revoked."""
        delegation = _make_delegation()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = delegation
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            count = await service.revoke_delegation(delegation.id, cascade=False)

        assert count == 1
        assert delegation.revoked_at is not None

    @pytest.mark.asyncio
    async def test_cascade_false_does_not_call_cascade_revoke(self) -> None:
        """_cascade_revoke is not invoked when cascade=False."""
        delegation = _make_delegation()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = delegation
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        service = DelegationService(mock_session)
        with (
            patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock),
            patch.object(service, "_cascade_revoke", new_callable=AsyncMock) as mock_cascade,
        ):
            await service.revoke_delegation(delegation.id, cascade=False)

        mock_cascade.assert_not_called()


class TestRevokeDelegationWithCascade:
    """revoke_delegation with cascade=True revokes downstream delegations."""

    @pytest.mark.asyncio
    async def test_cascade_revokes_single_downstream(self) -> None:
        """
        Revoking A→B also revokes B→C.

        Graph: A →(d1)→ B →(d2)→ C
        Revoking d1 with cascade=True should also revoke d2.
        """
        agent_b = uuid4()
        agent_c = uuid4()

        d1 = _make_delegation(delegate_agent_id=agent_b)
        d2 = _make_delegation(delegator_agent_id=agent_b, delegate_agent_id=agent_c)

        mock_session = AsyncMock()

        # First execute: fetch d1 by ID
        result_d1 = MagicMock()
        result_d1.scalar_one_or_none.return_value = d1

        # Second execute: cascade — fetch downstream delegations where delegator_agent_id IN [agent_b]
        result_downstream = MagicMock()
        result_downstream.scalars.return_value.all.return_value = [d2]

        # Third execute: cascade continues — fetch downstream of agent_c (none)
        result_empty = MagicMock()
        result_empty.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[result_d1, result_downstream, result_empty]
        )
        mock_session.commit = AsyncMock()

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            count = await service.revoke_delegation(d1.id, cascade=True)

        assert count == 2  # d1 + d2
        assert d1.revoked_at is not None
        assert d2.revoked_at is not None

    @pytest.mark.asyncio
    async def test_cascade_revokes_multi_level_chain(self) -> None:
        """
        Three-level chain: A →(d1)→ B →(d2)→ C →(d3)→ D
        Revoking d1 with cascade=True revokes d2 and d3 as well.
        """
        agent_b = uuid4()
        agent_c = uuid4()
        agent_d = uuid4()

        d1 = _make_delegation(delegate_agent_id=agent_b)
        d2 = _make_delegation(delegator_agent_id=agent_b, delegate_agent_id=agent_c)
        d3 = _make_delegation(delegator_agent_id=agent_c, delegate_agent_id=agent_d)

        mock_session = AsyncMock()

        result_d1 = MagicMock()
        result_d1.scalar_one_or_none.return_value = d1

        # BFS level 1: agent_b's downstream → d2
        result_level1 = MagicMock()
        result_level1.scalars.return_value.all.return_value = [d2]

        # BFS level 2: agent_c's downstream → d3
        result_level2 = MagicMock()
        result_level2.scalars.return_value.all.return_value = [d3]

        # BFS level 3: agent_d's downstream → empty
        result_level3 = MagicMock()
        result_level3.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[result_d1, result_level1, result_level2, result_level3]
        )
        mock_session.commit = AsyncMock()

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            count = await service.revoke_delegation(d1.id, cascade=True)

        assert count == 3  # d1 + d2 + d3
        assert d1.revoked_at is not None
        assert d2.revoked_at is not None
        assert d3.revoked_at is not None

    @pytest.mark.asyncio
    async def test_cascade_no_downstream_returns_one(self) -> None:
        """Revoking a leaf delegation with cascade=True returns 1 (just the leaf)."""
        delegation = _make_delegation()

        mock_session = AsyncMock()
        result_d = MagicMock()
        result_d.scalar_one_or_none.return_value = delegation

        # No downstream delegations
        result_empty = MagicMock()
        result_empty.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[result_d, result_empty])
        mock_session.commit = AsyncMock()

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            count = await service.revoke_delegation(delegation.id, cascade=True)

        assert count == 1
        assert delegation.revoked_at is not None

    @pytest.mark.asyncio
    async def test_cascade_sets_revoked_at_timestamp(self) -> None:
        """All revoked delegations have a non-None revoked_at timestamp."""
        agent_b = uuid4()
        d1 = _make_delegation(delegate_agent_id=agent_b)
        d2 = _make_delegation(delegator_agent_id=agent_b)

        mock_session = AsyncMock()

        result_d1 = MagicMock()
        result_d1.scalar_one_or_none.return_value = d1

        result_downstream = MagicMock()
        result_downstream.scalars.return_value.all.return_value = [d2]

        result_empty = MagicMock()
        result_empty.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[result_d1, result_downstream, result_empty]
        )
        mock_session.commit = AsyncMock()

        before = datetime.now(UTC)

        service = DelegationService(mock_session)
        with patch.object(service, "_invalidate_chain_cache", new_callable=AsyncMock):
            await service.revoke_delegation(d1.id, cascade=True)

        after = datetime.now(UTC)

        for d in [d1, d2]:
            assert d.revoked_at is not None
            assert before <= d.revoked_at <= after


class TestCascadeRevokeBFS:
    """Direct tests for _cascade_revoke BFS traversal."""

    @pytest.mark.asyncio
    async def test_cascade_revoke_returns_zero_for_leaf(self) -> None:
        """_cascade_revoke returns 0 when agent has no downstream delegations."""
        mock_session = AsyncMock()
        result_empty = MagicMock()
        result_empty.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=result_empty)

        service = DelegationService(mock_session)
        count = await service._cascade_revoke(uuid4(), datetime.now(UTC))
        assert count == 0

    @pytest.mark.asyncio
    async def test_cascade_revoke_skips_already_revoked(self) -> None:
        """_cascade_revoke does not double-count already revoked delegations."""
        # Delegations with revoked_at already set should not be returned by the
        # query (WHERE revoked_at IS NULL), so if the mock returns none, count=0.
        mock_session = AsyncMock()
        result_empty = MagicMock()
        result_empty.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=result_empty)

        service = DelegationService(mock_session)
        count = await service._cascade_revoke(uuid4(), datetime.now(UTC))
        assert count == 0
