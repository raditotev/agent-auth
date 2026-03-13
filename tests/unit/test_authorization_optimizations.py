"""Tests for authorization optimizations: merged query and cache versioning."""

from datetime import UTC
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from agentauth.models.policy import Policy, PolicyEffect
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


class TestMergedQuery:
    """Tests that _load_policies uses a single query instead of two."""

    @pytest.mark.asyncio
    async def test_load_policies_single_execute_call(self) -> None:
        """_load_policies calls session.execute exactly once (merged CTE + policy fetch)."""
        agent_id = uuid4()
        policy = Policy(
            id=uuid4(),
            created_by_agent_id=agent_id,
            name="test-policy",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = AuthorizationService(mock_session)
        policies = await service._load_policies(agent_id)

        # Must be exactly ONE call, not two
        assert mock_session.execute.call_count == 1
        assert len(policies) == 1
        assert policies[0].id == policy.id
        assert policies[0].name == "test-policy"

    @pytest.mark.asyncio
    async def test_load_policies_empty_result_returns_empty_list(self) -> None:
        """When the merged query returns no rows, _load_policies returns []."""
        agent_id = uuid4()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = AuthorizationService(mock_session)
        policies = await service._load_policies(agent_id)

        assert mock_session.execute.call_count == 1
        assert policies == []

    @pytest.mark.asyncio
    async def test_load_policies_maps_all_fields_correctly(self) -> None:
        """Verify all Policy fields are correctly mapped from query result rows."""
        agent_id = uuid4()
        creator_id = uuid4()
        policy_id = uuid4()

        policy = Policy(
            id=policy_id,
            created_by_agent_id=creator_id,
            name="full-field-test",
            description="Test all fields",
            effect=PolicyEffect.DENY,
            subjects={"agent_ids": [str(agent_id)]},
            resources={"paths": ["/api/v1/*"]},
            actions=["read", "write"],
            conditions={"ip_allowlist": ["10.0.0.1"]},
            priority=50,
            enabled=True,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = AuthorizationService(mock_session)
        policies = await service._load_policies(agent_id)

        loaded = policies[0]
        assert loaded.id == policy_id
        assert loaded.created_by_agent_id == creator_id
        assert loaded.name == "full-field-test"
        assert loaded.description == "Test all fields"
        assert loaded.effect == PolicyEffect.DENY
        assert loaded.subjects == {"agent_ids": [str(agent_id)]}
        assert loaded.resources == {"paths": ["/api/v1/*"]}
        assert loaded.actions == ["read", "write"]
        assert loaded.conditions == {"ip_allowlist": ["10.0.0.1"]}
        assert loaded.priority == 50
        assert loaded.enabled is True


class TestCacheVersioning:
    """Tests for policy cache versioning."""

    @pytest.mark.asyncio
    async def test_cache_key_includes_version(self) -> None:
        """Cache key includes version from Redis policy_version counter."""
        agent_id = uuid4()
        policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="versioned-policy",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value="3")
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.set_json = AsyncMock(return_value=True)

        with patch("agentauth.core.redis.get_redis_client", return_value=mock_redis):
            service = AuthorizationService(mock_session)
            await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        # Verify set_json was called with a versioned cache key
        set_json_call = mock_redis.set_json.call_args
        cache_key = set_json_call[0][0]
        assert cache_key.startswith(f"authz:v3d3:{agent_id}:")

    @pytest.mark.asyncio
    async def test_version_change_bypasses_old_cache(self) -> None:
        """After policy version increment, old cached entries are bypassed."""
        agent_id = uuid4()
        policy = Policy(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="policy",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [_policy_to_row(policy)]
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Simulate: version was "1" when cached, now version is "2"
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value="2")  # version is now 2
        mock_redis.get_json = AsyncMock(return_value=None)  # no cache at v2 key
        mock_redis.set_json = AsyncMock(return_value=True)

        with patch("agentauth.core.redis.get_redis_client", return_value=mock_redis):
            service = AuthorizationService(mock_session)
            result = await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        # Should have gone to DB (cache miss at new version), not returned stale data
        assert mock_session.execute.call_count == 1
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_default_version_zero_when_no_counter(self) -> None:
        """When policy_version key doesn't exist, version defaults to '0'."""
        agent_id = uuid4()

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)  # No version key
        mock_redis.get_json = AsyncMock(return_value=None)
        mock_redis.set_json = AsyncMock(return_value=True)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("agentauth.core.redis.get_redis_client", return_value=mock_redis):
            service = AuthorizationService(mock_session)
            await service.evaluate(
                agent_id=agent_id,
                action="read",
                resource="/api/v1/agents",
            )

        # Cache key should use v0
        set_json_call = mock_redis.set_json.call_args
        cache_key = set_json_call[0][0]
        assert cache_key.startswith(f"authz:v0d0:{agent_id}:")

    @pytest.mark.asyncio
    async def test_increment_policy_version_calls_redis_incr(self) -> None:
        """_increment_policy_version calls redis.incr with the correct key."""
        agent_id = uuid4()

        mock_redis = AsyncMock()
        mock_redis.incr = AsyncMock(return_value=1)

        with patch("agentauth.core.redis.get_redis_client", return_value=mock_redis):
            await AuthorizationService._increment_policy_version(agent_id)

        mock_redis.incr.assert_called_once_with(f"policy_version:{agent_id}")


class TestPolicyCrudVersionIncrement:
    """Tests that policy CRUD endpoints increment the version counter."""

    @pytest.mark.asyncio
    async def test_create_policy_increments_version(self) -> None:
        """Creating a policy calls _increment_policy_version for the creator."""
        from datetime import datetime

        from agentauth.api.v1.policies import create_policy
        from agentauth.schemas.policy import PolicyCreate

        actor_id = uuid4()
        policy_id = uuid4()
        now = datetime.now(UTC)

        payload = PolicyCreate(
            name="test-policy",
            effect=PolicyEffect.ALLOW,
            subjects={"wildcard": True},
            resources={"wildcard": True},
            actions=["read"],
            conditions={},
            priority=10,
            enabled=True,
        )

        mock_policy = MagicMock(spec=Policy)
        mock_policy.id = policy_id
        mock_policy.created_by_agent_id = actor_id
        mock_policy.name = "test-policy"
        mock_policy.description = ""
        mock_policy.effect = PolicyEffect.ALLOW
        mock_policy.subjects = {"wildcard": True}
        mock_policy.resources = {"wildcard": True}
        mock_policy.actions = ["read"]
        mock_policy.conditions = {}
        mock_policy.priority = 10
        mock_policy.enabled = True
        mock_policy.created_at = now
        mock_policy.updated_at = now

        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()
        mock_session.add = MagicMock()

        mock_request = MagicMock()
        mock_request.state.agent_id = actor_id

        with (
            patch("agentauth.api.v1.policies.Policy", return_value=mock_policy),
            patch(
                "agentauth.api.v1.policies._invalidate_policy_cache",
                new_callable=AsyncMock,
            ) as mock_invalidate,
        ):
            await create_policy(payload, mock_session, mock_request)

        mock_invalidate.assert_called_once_with(actor_id)

    @pytest.mark.asyncio
    async def test_update_policy_increments_version(self) -> None:
        """Updating a policy calls _invalidate_policy_cache with created_by_agent_id."""
        from datetime import datetime

        from agentauth.api.v1.policies import update_policy
        from agentauth.schemas.policy import PolicyUpdate

        creator_id = uuid4()
        policy_id = uuid4()
        now = datetime.now(UTC)

        payload = PolicyUpdate(name="updated-name")

        mock_policy = MagicMock(spec=Policy)
        mock_policy.id = policy_id
        mock_policy.created_by_agent_id = creator_id
        mock_policy.name = "updated-name"
        mock_policy.description = ""
        mock_policy.effect = PolicyEffect.ALLOW
        mock_policy.subjects = {}
        mock_policy.resources = {}
        mock_policy.actions = []
        mock_policy.conditions = {}
        mock_policy.priority = 10
        mock_policy.enabled = True
        mock_policy.created_at = now
        mock_policy.updated_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_policy

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        with patch(
            "agentauth.api.v1.policies._invalidate_policy_cache",
            new_callable=AsyncMock,
        ) as mock_invalidate:
            await update_policy(policy_id, payload, mock_session)

        mock_invalidate.assert_called_once_with(creator_id)

    @pytest.mark.asyncio
    async def test_delete_policy_increments_version(self) -> None:
        """Deleting a policy calls _invalidate_policy_cache with created_by_agent_id."""
        from agentauth.api.v1.policies import delete_policy

        creator_id = uuid4()
        policy_id = uuid4()

        mock_policy = MagicMock(spec=Policy)
        mock_policy.id = policy_id
        mock_policy.created_by_agent_id = creator_id

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_policy

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.delete = AsyncMock()
        mock_session.commit = AsyncMock()

        with patch(
            "agentauth.api.v1.policies._invalidate_policy_cache",
            new_callable=AsyncMock,
        ) as mock_invalidate:
            await delete_policy(policy_id, mock_session)

        mock_invalidate.assert_called_once_with(creator_id)
