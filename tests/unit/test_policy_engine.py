"""Unit tests for AuthorizationService (policy evaluation engine)."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from agentauth.models.policy import Policy, PolicyEffect
from agentauth.schemas.policy import PolicyEvaluateResponse
from agentauth.services.authorization import AuthorizationService


def _policy_to_row(policy: Policy) -> tuple:
    """Convert a Policy object to a row tuple matching the combined CTE query columns."""
    return (
        policy.id,
        policy.created_by_agent_id,
        policy.name,
        policy.description,
        policy.effect,
        policy.subjects,
        policy.resources,
        policy.actions,
        policy.conditions,
        policy.priority,
        policy.enabled,
        getattr(policy, "created_at", None),
        getattr(policy, "updated_at", None),
    )


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
        mock_result.fetchall.return_value = [
            _policy_to_row(deny_policy),
            _policy_to_row(allow_policy),
        ]
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
        agent_id = uuid4()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
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
        agent_id = uuid4()  # Different from policy's agent_ids

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
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
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
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


class TestPolicyScoping:
    """Tests that _load_policies only returns policies from the agent's trust chain."""

    @pytest.mark.asyncio
    async def test_policies_scoped_to_ancestor_chain(self) -> None:
        """Only policies created by agents in the ancestor chain are loaded."""
        agent_id = uuid4()
        ancestor_id = uuid4()
        unrelated_id = uuid4()

        # Policy created by an ancestor — should be visible
        ancestor_policy = Policy(
            id=uuid4(),
            created_by_agent_id=ancestor_id,
            name="ancestor-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )
        # Policy from an unrelated tree — must NOT be visible
        _unrelated_policy = Policy(
            id=uuid4(),
            created_by_agent_id=unrelated_id,
            name="unrelated-deny",
            effect=PolicyEffect.DENY,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["*"],
            conditions={},
            priority=100,
            enabled=True,
        )

        mock_session = AsyncMock()

        # Combined query returns only ancestor_policy (unrelated excluded by DB query)
        combined_result = MagicMock()
        combined_result.fetchall.return_value = [_policy_to_row(ancestor_policy)]

        mock_session.execute = AsyncMock(return_value=combined_result)

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

        # Should allow because ancestor_policy matches and unrelated_deny is excluded
        assert result.allowed is True
        assert result.matching_policy_id == ancestor_policy.id

    @pytest.mark.asyncio
    async def test_no_ancestor_ids_returns_default_deny(self) -> None:
        """When the CTE returns no rows (e.g. unknown agent), default deny applies."""
        agent_id = uuid4()

        mock_session = AsyncMock()

        # Combined query returns empty — agent not found or no policies
        empty_result = MagicMock()
        empty_result.fetchall.return_value = []

        mock_session.execute = AsyncMock(return_value=empty_result)

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
        assert "default deny" in result.reason.lower()


class TestPolicyScopingViolations:
    """Tests that policies from sibling/unrelated trees cannot affect other agents."""

    @pytest.mark.asyncio
    async def test_sibling_tree_deny_does_not_apply(self) -> None:
        """
        A DENY policy created by a sibling-tree agent must not affect the requesting agent.

        Tree layout:
          root_a → agent_a   (requesting agent)
          root_b → agent_b   (unrelated sibling tree)

        A DENY policy created by root_b/agent_b must be invisible to agent_a.
        """
        agent_a = uuid4()
        root_a = uuid4()
        agent_b = uuid4()

        # The sibling DENY policy explicitly names agent_a in subjects — it still
        # must be excluded because root_b is not in agent_a's ancestor chain.
        sibling_deny = Policy(  # noqa: F841
            id=uuid4(),
            created_by_agent_id=agent_b,  # Different tree
            name="sibling-deny",
            effect=PolicyEffect.DENY,
            subjects={"agent_ids": [str(agent_a)]},  # Explicitly targets agent_a
            resources={"wildcard": True},
            actions=["*"],
            conditions={},
            priority=999,
            enabled=True,
        )
        ancestor_allow = Policy(
            id=uuid4(),
            created_by_agent_id=root_a,
            name="ancestor-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_session = AsyncMock()

        # Combined query returns only ancestor_allow (sibling_deny excluded by the CTE)
        combined_result = MagicMock()
        combined_result.fetchall.return_value = [_policy_to_row(ancestor_allow)]

        mock_session.execute = AsyncMock(return_value=combined_result)

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
                agent_id=agent_a,
                action="read",
                resource="/api/v1/agents",
            )

        # Sibling DENY is excluded → ancestor ALLOW wins
        assert result.allowed is True
        assert result.matching_policy_id == ancestor_allow.id

    @pytest.mark.asyncio
    async def test_only_self_in_ancestor_chain(self) -> None:
        """
        A root agent (no parent) only sees policies it created itself.
        """
        root_agent = uuid4()
        other_root = uuid4()  # noqa: F841

        own_allow = Policy(
            id=uuid4(),
            created_by_agent_id=root_agent,
            name="own-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_session = AsyncMock()

        # Combined query returns own_allow only (other_root's policies excluded)
        combined_result = MagicMock()
        combined_result.fetchall.return_value = [_policy_to_row(own_allow)]

        mock_session.execute = AsyncMock(return_value=combined_result)

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
                agent_id=root_agent,
                action="read",
                resource="/api/v1/agents",
            )

        assert result.allowed is True
        assert result.matching_policy_id == own_allow.id

    @pytest.mark.asyncio
    async def test_disabled_policy_in_ancestor_chain_excluded(self) -> None:
        """
        A disabled policy (enabled=False) from the agent's own ancestor chain
        must NOT affect the decision — only enabled policies are loaded.
        """
        agent_id = uuid4()
        ancestor_id = uuid4()

        # Disabled ALLOW from own ancestor — must be excluded
        disabled_allow = Policy(  # noqa: F841
            id=uuid4(),
            created_by_agent_id=ancestor_id,
            name="disabled-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=False,  # disabled
        )

        mock_session = AsyncMock()

        # Combined query excludes disabled policies (WHERE enabled IS TRUE) → empty result
        combined_result = MagicMock()
        combined_result.fetchall.return_value = []

        mock_session.execute = AsyncMock(return_value=combined_result)

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

        # No enabled policies → default deny
        assert result.allowed is False
        assert result.matching_policy_id is None
        assert "default deny" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_deeply_nested_agent_scoped_to_full_ancestor_chain(self) -> None:
        """
        An agent three levels deep sees policies from all three ancestors.
        Sibling chains at the same depth are excluded.
        """
        root = uuid4()
        parent = uuid4()
        agent = uuid4()
        sibling_root = uuid4()  # noqa: F841

        ancestor_allow = Policy(
            id=uuid4(),
            created_by_agent_id=root,
            name="root-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=5,
            enabled=True,
        )
        parent_restrict = Policy(
            id=uuid4(),
            created_by_agent_id=parent,
            name="parent-restrict",
            effect=PolicyEffect.DENY,
            subjects={"wildcard": True},
            resources={"paths": ["/api/v1/admin/*"]},
            actions=["*"],
            conditions={},
            priority=50,
            enabled=True,
        )

        mock_session = AsyncMock()

        # Combined query returns both own-tree policies (sibling_root's excluded)
        # parent_restrict has higher priority — evaluated first
        combined_result = MagicMock()
        combined_result.fetchall.return_value = [
            _policy_to_row(parent_restrict),
            _policy_to_row(ancestor_allow),
        ]

        mock_session.execute = AsyncMock(return_value=combined_result)

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
            # Accessing admin resource — hits parent_restrict DENY
            result = await service.evaluate(
                agent_id=agent,
                action="delete",
                resource="/api/v1/admin/users",
            )

        assert result.allowed is False
        assert result.matching_policy_id == parent_restrict.id

    @pytest.mark.asyncio
    async def test_unrelated_allow_does_not_grant_access(self) -> None:
        """
        An ALLOW policy from an unrelated tree must not grant access even when it
        would otherwise match action/resource/subjects.
        """
        agent_id = uuid4()
        unrelated_creator = uuid4()

        # This policy matches the agent by ID but comes from unrelated tree
        unrelated_allow = Policy(  # noqa: F841
            id=uuid4(),
            created_by_agent_id=unrelated_creator,
            name="unrelated-allow",
            effect=PolicyEffect.ALLOW,
            subjects={"agent_ids": [str(agent_id)]},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=100,
            enabled=True,
        )

        mock_session = AsyncMock()

        # Combined query excludes unrelated_allow → empty
        combined_result = MagicMock()
        combined_result.fetchall.return_value = []

        mock_session.execute = AsyncMock(return_value=combined_result)

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
        assert "default deny" in result.reason.lower()


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
