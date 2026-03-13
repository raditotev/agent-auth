"""Unit tests for delegation chain depth semantics (Task 9.3)."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agentauth.schemas.delegation import DelegationResponse


def _make_delegation_ns(
    *,
    chain_depth: int,
    max_chain_depth: int,
) -> SimpleNamespace:
    """Build a minimal delegation-like namespace for schema tests."""
    d = SimpleNamespace()
    d.id = uuid4()
    d.delegator_agent_id = uuid4()
    d.delegate_agent_id = uuid4()
    d.scopes = ["api.read"]
    d.constraints = {}
    d.chain_depth = chain_depth
    d.max_chain_depth = max_chain_depth
    d.expires_at = None
    d.revoked_at = None
    d.created_at = datetime.now(UTC)
    d.updated_at = datetime.now(UTC)
    d.is_active = lambda: True
    return d


class TestChainDepthRemaining:
    """chain_depth_remaining is correctly computed as max_chain_depth - chain_depth."""

    def test_chain_depth_remaining_mid_chain(self) -> None:
        ns = _make_delegation_ns(chain_depth=1, max_chain_depth=3)
        resp = DelegationResponse.from_model(ns)
        assert resp.chain_depth_remaining == 2

    def test_chain_depth_remaining_at_root(self) -> None:
        ns = _make_delegation_ns(chain_depth=0, max_chain_depth=5)
        resp = DelegationResponse.from_model(ns)
        assert resp.chain_depth_remaining == 5

    def test_chain_depth_remaining_at_max_depth(self) -> None:
        """When chain_depth equals max_chain_depth, remaining must be 0."""
        ns = _make_delegation_ns(chain_depth=3, max_chain_depth=3)
        resp = DelegationResponse.from_model(ns)
        assert resp.chain_depth_remaining == 0

    def test_chain_depth_remaining_never_negative(self) -> None:
        """chain_depth_remaining is floored at 0 even if chain_depth > max_chain_depth."""
        ns = _make_delegation_ns(chain_depth=5, max_chain_depth=3)
        resp = DelegationResponse.from_model(ns)
        assert resp.chain_depth_remaining == 0


class TestMaxAbsoluteChainDepth:
    """max_absolute_chain_depth equals max_chain_depth."""

    def test_max_absolute_chain_depth_alias(self) -> None:
        ns = _make_delegation_ns(chain_depth=1, max_chain_depth=7)
        resp = DelegationResponse.from_model(ns)
        assert resp.max_absolute_chain_depth == resp.max_chain_depth

    def test_max_absolute_chain_depth_zero(self) -> None:
        ns = _make_delegation_ns(chain_depth=0, max_chain_depth=0)
        resp = DelegationResponse.from_model(ns)
        assert resp.max_absolute_chain_depth == 0
        assert resp.chain_depth_remaining == 0


class TestChainDepthExceededError:
    """ValidationError is raised with structured detail on depth exceeded."""

    @pytest.mark.asyncio
    async def test_chain_depth_exceeded_raises_validation_error(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        from agentauth.core.exceptions import ValidationError
        from agentauth.services.delegation import DelegationService

        session = MagicMock()
        # Simulate a delegator that already has chain_depth == max_chain_depth (3)
        existing_delegation = _make_delegation_ns(chain_depth=3, max_chain_depth=3)
        existing_delegation.is_active = lambda: True

        # No incoming delegations needed; root agent path with chain_depth=0 will be used
        # instead just mock the DB to return a delegator at depth 3
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [existing_delegation]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute = AsyncMock(return_value=result_mock)

        service = DelegationService(session)

        with pytest.raises(ValidationError) as exc_info:
            await service.create_delegation(
                delegator_agent_id=existing_delegation.delegator_agent_id,
                delegate_agent_id=uuid4(),
                scopes=["api.read"],
                max_chain_depth=3,
            )

        err = exc_info.value
        assert "chain_depth_exceeded" in str(err)
        assert err.detail["chain_depth_remaining"] == 0
        assert "effective_max_chain_depth" in err.detail
