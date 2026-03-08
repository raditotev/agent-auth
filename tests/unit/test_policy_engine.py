"""Unit tests for AuthorizationService (policy evaluation engine)."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from agentauth.models.policy import Policy, PolicyEffect
from agentauth.schemas.policy import PolicyEvaluateResponse
from agentauth.services.authorization import AuthorizationService


class TestPolicyMatchingHelpers:
    """Tests for static matching helpers."""

    def test_matches_subjects_empty_matches_any_agent(self) -> None:
        """Empty subjects dict matches any agent."""
        agent_id = uuid4()
        assert AuthorizationService._matches_subjects({}, agent_id) is True

    def test_matches_subjects_wildcard_matches_any_agent(self) -> None:
        """wildcard: true matches any agent."""
        agent_id = uuid4()
        assert AuthorizationService._matches_subjects({"wildcard": True}, agent_id) is True

    def test_matches_subjects_agent_ids_match_explicit(self) -> None:
        """agent_ids list matches when agent ID is in list."""
        agent_id = uuid4()
        assert (
            AuthorizationService._matches_subjects({"agent_ids": [str(agent_id)]}, agent_id) is True
        )

    def test_matches_subjects_agent_ids_no_match(self) -> None:
        """agent_ids list does not match when agent ID not in list."""
        agent_id = uuid4()
        other_id = uuid4()
        assert (
            AuthorizationService._matches_subjects({"agent_ids": [str(other_id)]}, agent_id)
            is False
        )

    def test_matches_actions_empty_matches_all(self) -> None:
        """Empty actions list matches any action."""
        assert AuthorizationService._matches_actions([], "read") is True
        assert AuthorizationService._matches_actions([], "write") is True

    def test_matches_actions_explicit_match(self) -> None:
        """Action in list matches."""
        assert AuthorizationService._matches_actions(["read", "write"], "read") is True
        assert AuthorizationService._matches_actions(["read", "write"], "write") is True

    def test_matches_actions_no_match(self) -> None:
        """Action not in list does not match."""
        assert AuthorizationService._matches_actions(["read"], "write") is False

    def test_matches_actions_wildcard_matches_all(self) -> None:
        """'*' in actions matches any action."""
        assert AuthorizationService._matches_actions(["*"], "read") is True
        assert AuthorizationService._matches_actions(["*"], "admin") is True
        assert AuthorizationService._matches_actions(["read", "*"], "delete") is True

    def test_matches_resources_empty_matches_any(self) -> None:
        """Empty resources dict matches any resource."""
        assert AuthorizationService._matches_resources({}, "/api/v1/agents") is True

    def test_matches_resources_wildcard_matches_any(self) -> None:
        """wildcard: true matches any resource."""
        assert (
            AuthorizationService._matches_resources({"wildcard": True}, "/api/v1/credentials")
            is True
        )

    def test_matches_resources_paths_exact_match(self) -> None:
        """Exact path match."""
        assert (
            AuthorizationService._matches_resources({"paths": ["/api/v1/agents"]}, "/api/v1/agents")
            is True
        )

    def test_matches_resources_paths_prefix_wildcard(self) -> None:
        """Path with '*' suffix matches prefix."""
        assert (
            AuthorizationService._matches_resources({"paths": ["/api/v1/*"]}, "/api/v1/agents")
            is True
        )
        assert (
            AuthorizationService._matches_resources(
                {"paths": ["/api/v1/credentials/*"]}, "/api/v1/credentials/123"
            )
            is True
        )

    def test_matches_resources_paths_no_match(self) -> None:
        """Path does not match when no pattern matches."""
        assert (
            AuthorizationService._matches_resources(
                {"paths": ["/api/v1/agents"]}, "/api/v1/credentials"
            )
            is False
        )
        assert (
            AuthorizationService._matches_resources({"paths": ["/api/v1/*"]}, "/other/path")
            is False
        )

    def test_matches_conditions_empty_passes(self) -> None:
        """Empty conditions always pass."""
        assert AuthorizationService._matches_conditions({}, {}) is True
        assert AuthorizationService._matches_conditions({}, {"ip": "1.2.3.4"}) is True

    def test_matches_conditions_ip_allowlist_match(self) -> None:
        """IP in allowlist passes."""
        assert (
            AuthorizationService._matches_conditions(
                {"ip_allowlist": ["10.0.0.1", "192.168.1.1"]},
                {"ip": "10.0.0.1"},
            )
            is True
        )

    def test_matches_conditions_ip_allowlist_no_match(self) -> None:
        """IP not in allowlist fails."""
        assert (
            AuthorizationService._matches_conditions(
                {"ip_allowlist": ["10.0.0.1"]},
                {"ip": "10.0.0.2"},
            )
            is False
        )

    def test_matches_conditions_ip_missing_fails(self) -> None:
        """When ip_allowlist is set but context has no ip, fails."""
        assert (
            AuthorizationService._matches_conditions(
                {"ip_allowlist": ["10.0.0.1"]},
                {},
            )
            is False
        )


class TestDenyOverrides:
    """Tests for deny-overrides combining algorithm."""

    @pytest.mark.asyncio
    async def test_deny_overrides_allow(self) -> None:
        """Matching DENY policy overrides matching ALLOW policy."""
        agent_id = uuid4()
        agent_id_str = str(agent_id)
        allow_policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="allow-policy",
            effect=PolicyEffect.ALLOW,
            subjects={"agent_ids": [agent_id_str]},
            resources={"paths": ["/api/v1/*"]},
            actions=["read", "write"],
            conditions={},
            priority=10,
            enabled=True,
        )
        deny_policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="deny-policy",
            effect=PolicyEffect.DENY,
            subjects={"agent_ids": [agent_id_str]},
            resources={"paths": ["/api/v1/credentials/*"]},
            actions=["read", "write"],
            conditions={},
            priority=100,  # Higher priority — evaluated first
            enabled=True,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [deny_policy, allow_policy]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with (
            patch(
                "agentauth.services.authorization.AuthorizationService._get_cached_decision",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "agentauth.services.authorization.AuthorizationService._cache_decision",
                new_callable=AsyncMock,
            ),
        ):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/credentials/123",
            )

        assert result.allowed is False
        assert result.effect == "deny"
        assert result.matching_policy_id == deny_policy.id
        assert "deny-policy" in result.reason


class TestDefaultDeny:
    """Tests for default-deny when no policy matches."""

    @pytest.mark.asyncio
    async def test_default_deny_when_no_policies(self) -> None:
        """No policies → default deny."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        agent_id = uuid4()
        with (
            patch(
                "agentauth.services.authorization.AuthorizationService._get_cached_decision",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "agentauth.services.authorization.AuthorizationService._cache_decision",
                new_callable=AsyncMock,
            ),
        ):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        assert result.allowed is False
        assert result.effect == "deny"
        assert result.matching_policy_id is None
        assert "default deny" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_default_deny_when_no_policy_matches(self) -> None:
        """Policies exist but none match → default deny."""
        policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="other-agent-policy",
            effect=PolicyEffect.ALLOW,
            subjects={"agent_ids": ["00000000-0000-0000-0000-000000000000"]},
            resources={"paths": ["/api/v1/*"]},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [policy]
        mock_session.execute = AsyncMock(return_value=mock_result)

        agent_id = uuid4()  # Different from policy's agent_ids
        with (
            patch(
                "agentauth.services.authorization.AuthorizationService._get_cached_decision",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "agentauth.services.authorization.AuthorizationService._cache_decision",
                new_callable=AsyncMock,
            ),
        ):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        assert result.allowed is False
        assert result.effect == "deny"
        assert "default deny" in result.reason.lower()


class TestAllowWhenMatch:
    """Tests for allow when policy matches."""

    @pytest.mark.asyncio
    async def test_allow_when_policy_matches(self) -> None:
        """Matching ALLOW policy grants access."""
        agent_id = uuid4()
        policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="allow-read",
            effect=PolicyEffect.ALLOW,
            subjects={"agent_ids": [str(agent_id)]},
            resources={"paths": ["/api/v1/agents"]},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [policy]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with (
            patch(
                "agentauth.services.authorization.AuthorizationService._get_cached_decision",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "agentauth.services.authorization.AuthorizationService._cache_decision",
                new_callable=AsyncMock,
            ),
        ):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        assert result.allowed is True
        assert result.effect == "allow"
        assert result.matching_policy_id == policy.id
        assert "allow-read" in result.reason


class TestCaching:
    """Tests for Redis caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_decision(self) -> None:
        """When cache has a hit, return cached result without DB query."""
        agent_id = uuid4()
        cached = PolicyEvaluateResponse(
            allowed=True,
            effect="allow",
            matching_policy_id=None,
            matching_policy_name="cached",
            reason="Cached decision",
        )

        mock_session = AsyncMock()
        with (
            patch(
                "agentauth.services.authorization.AuthorizationService._get_cached_decision",
                new_callable=AsyncMock,
                return_value=cached,
            ),
            patch(
                "agentauth.services.authorization.AuthorizationService._cache_decision",
                new_callable=AsyncMock,
            ),
        ):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        assert result.allowed is True
        assert result.reason == "Cached decision"
        mock_session.execute.assert_not_called()
