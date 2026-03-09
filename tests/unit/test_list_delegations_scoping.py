"""Unit tests for list_delegations access control scoping (task 5.2)."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from agentauth.api.v1.delegations import list_delegations
from agentauth.schemas.delegation import DelegationListResponse


def _make_agent(
    *,
    agent_id: UUID | None = None,
    parent_agent_id: UUID | None = None,
    trust_level: str = "delegated",
) -> SimpleNamespace:
    """Build a lightweight agent-like namespace."""
    a = SimpleNamespace()
    a.id = agent_id or uuid4()
    a.parent_agent_id = parent_agent_id
    a.trust_level = SimpleNamespace(value=trust_level)
    a.is_root = lambda: parent_agent_id is None and trust_level == "root"
    return a


def _make_delegation(
    *,
    delegation_id: UUID | None = None,
    delegator_agent_id: UUID | None = None,
    delegate_agent_id: UUID | None = None,
    revoked: bool = False,
) -> SimpleNamespace:
    """Build a lightweight delegation-like namespace."""
    d = SimpleNamespace()
    d.id = delegation_id or uuid4()
    d.delegator_agent_id = delegator_agent_id or uuid4()
    d.delegate_agent_id = delegate_agent_id or uuid4()
    d.scopes = ["read"]
    d.constraints = {}
    d.chain_depth = 1
    d.max_chain_depth = 3
    d.expires_at = None
    d.revoked_at = datetime.now(UTC) if revoked else None
    d.created_at = datetime.now(UTC)
    d.updated_at = datetime.now(UTC)
    d.is_active = lambda: not revoked
    return d


def _make_request(agent: SimpleNamespace) -> SimpleNamespace:
    """Build a minimal Request-like object with agent on state."""
    req = SimpleNamespace()
    req.state = SimpleNamespace(agent=agent)
    return req


class TestListDelegationsRootAgent:
    """Root agents should see all delegations system-wide."""

    @pytest.mark.asyncio
    async def test_root_agent_sees_all_delegations(self) -> None:
        """Root agent gets all delegations without subtree filtering."""
        root = _make_agent(trust_level="root")
        d1 = _make_delegation()
        d2 = _make_delegation()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d1, d2]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(root)

        with patch("agentauth.api.v1.delegations.IdentityService") as MockIdentityService:
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )
            # IdentityService.get_subtree_agent_ids must NOT be called for root
            MockIdentityService.assert_not_called()

        assert isinstance(response, DelegationListResponse)
        assert response.total == 2
        assert len(response.data) == 2

    @pytest.mark.asyncio
    async def test_root_agent_active_only_filters_revoked(self) -> None:
        """Root agent with active_only=True does not see revoked delegations."""
        root = _make_agent(trust_level="root")
        d_active = _make_delegation(revoked=False)
        d_revoked = _make_delegation(revoked=True)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_active, d_revoked]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(root)

        with patch("agentauth.api.v1.delegations.IdentityService"):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=True,
            )

        assert response.total == 1
        assert response.data[0].id == d_active.id


class TestListDelegationsNonRootAgent:
    """Non-root agents should only see delegations in their subtree."""

    @pytest.mark.asyncio
    async def test_non_root_agent_triggers_subtree_filter(self) -> None:
        """Non-root agent causes IdentityService.get_subtree_agent_ids to be called."""
        caller = _make_agent(parent_agent_id=uuid4(), trust_level="delegated")
        d1 = _make_delegation()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d1]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(caller)

        mock_identity_service = AsyncMock()
        mock_identity_service.get_subtree_agent_ids = AsyncMock(return_value=[caller.id])

        with patch(
            "agentauth.api.v1.delegations.IdentityService",
            return_value=mock_identity_service,
        ):
            await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )
            mock_identity_service.get_subtree_agent_ids.assert_called_once_with(caller.id)

    @pytest.mark.asyncio
    async def test_non_root_sees_own_delegations_as_delegator(self) -> None:
        """Caller sees delegations where they are the delegator."""
        caller_id = uuid4()
        other_id = uuid4()
        caller = _make_agent(agent_id=caller_id, parent_agent_id=uuid4(), trust_level="delegated")

        # Delegation where caller is delegator
        d_own = _make_delegation(delegator_agent_id=caller_id, delegate_agent_id=other_id)
        # Delegation in an unrelated subtree — would be filtered out by the SQL WHERE
        # clause but here we simulate the DB already returning only scoped rows
        d_unrelated = _make_delegation()

        # Simulate DB returning only scoped delegations (caller in subtree)
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_own]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(caller)

        mock_identity_service = AsyncMock()
        mock_identity_service.get_subtree_agent_ids = AsyncMock(return_value=[caller_id])

        with patch(
            "agentauth.api.v1.delegations.IdentityService",
            return_value=mock_identity_service,
        ):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )

        assert response.total == 1
        assert response.data[0].delegator_agent_id == caller_id

    @pytest.mark.asyncio
    async def test_non_root_sees_own_delegations_as_delegate(self) -> None:
        """Caller sees delegations where they are the delegate."""
        caller_id = uuid4()
        other_id = uuid4()
        caller = _make_agent(agent_id=caller_id, parent_agent_id=uuid4(), trust_level="delegated")

        d_incoming = _make_delegation(delegator_agent_id=other_id, delegate_agent_id=caller_id)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_incoming]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(caller)

        mock_identity_service = AsyncMock()
        mock_identity_service.get_subtree_agent_ids = AsyncMock(return_value=[caller_id])

        with patch(
            "agentauth.api.v1.delegations.IdentityService",
            return_value=mock_identity_service,
        ):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )

        assert response.total == 1
        assert response.data[0].delegate_agent_id == caller_id

    @pytest.mark.asyncio
    async def test_non_root_sees_descendant_delegations(self) -> None:
        """Caller sees delegations involving their descendants."""
        caller_id = uuid4()
        child_id = uuid4()
        other_id = uuid4()
        caller = _make_agent(agent_id=caller_id, parent_agent_id=uuid4(), trust_level="delegated")

        # Delegation between child and some other agent
        d_child = _make_delegation(delegator_agent_id=child_id, delegate_agent_id=other_id)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_child]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(caller)

        mock_identity_service = AsyncMock()
        # Subtree includes caller and child
        mock_identity_service.get_subtree_agent_ids = AsyncMock(
            return_value=[caller_id, child_id]
        )

        with patch(
            "agentauth.api.v1.delegations.IdentityService",
            return_value=mock_identity_service,
        ):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )

        assert response.total == 1

    @pytest.mark.asyncio
    async def test_non_root_cannot_see_unrelated_delegations(self) -> None:
        """Delegations outside the caller's subtree are not returned."""
        caller_id = uuid4()
        caller = _make_agent(agent_id=caller_id, parent_agent_id=uuid4(), trust_level="delegated")

        # The DB query (with the WHERE filter) would return no rows for unrelated delegations
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(caller)

        mock_identity_service = AsyncMock()
        mock_identity_service.get_subtree_agent_ids = AsyncMock(return_value=[caller_id])

        with patch(
            "agentauth.api.v1.delegations.IdentityService",
            return_value=mock_identity_service,
        ):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )

        assert response.total == 0
        assert response.data == []


class TestListDelegationsUnauthenticated:
    """Unauthenticated requests must be rejected with 401."""

    @pytest.mark.asyncio
    async def test_no_agent_on_request_state_raises_401(self) -> None:
        """Missing agent on request.state raises HTTP 401."""
        from fastapi import HTTPException

        request = SimpleNamespace(state=SimpleNamespace(agent=None))
        mock_session = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await list_delegations(
                request=request,
                session=mock_session,
                active_only=True,
            )

        assert exc_info.value.status_code == 401


class TestListDelegationsActiveOnlyFlag:
    """active_only flag continues to work correctly after scoping."""

    @pytest.mark.asyncio
    async def test_active_only_false_includes_revoked(self) -> None:
        """active_only=False returns both active and revoked delegations."""
        root = _make_agent(trust_level="root")
        d_active = _make_delegation(revoked=False)
        d_revoked = _make_delegation(revoked=True)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_active, d_revoked]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(root)

        with patch("agentauth.api.v1.delegations.IdentityService"):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=False,
            )

        assert response.total == 2

    @pytest.mark.asyncio
    async def test_active_only_true_excludes_revoked(self) -> None:
        """active_only=True filters out revoked delegations."""
        root = _make_agent(trust_level="root")
        d_active = _make_delegation(revoked=False)
        d_revoked = _make_delegation(revoked=True)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [d_active, d_revoked]
        mock_session.execute = AsyncMock(return_value=mock_result)

        request = _make_request(root)

        with patch("agentauth.api.v1.delegations.IdentityService"):
            response = await list_delegations(
                request=request,
                session=mock_session,
                active_only=True,
            )

        assert response.total == 1
        assert response.data[0].id == d_active.id
