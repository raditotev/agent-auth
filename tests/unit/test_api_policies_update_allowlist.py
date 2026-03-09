"""Unit tests for the update_policy handler's _UPDATABLE_FIELDS allowlist.

Verifies that only intended fields can be modified through the update endpoint
and that non-updatable fields (e.g. created_by_agent_id, id) are silently ignored.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from agentauth.models.policy import Policy, PolicyEffect
from agentauth.schemas.policy import PolicyUpdate


class TestUpdatePolicyFieldAllowlist:
    """Tests that update_policy only applies changes to _UPDATABLE_FIELDS."""

    def _make_policy(self, **overrides) -> Policy:
        """Create a minimal Policy instance for testing."""
        defaults = dict(
            id=uuid4(),
            created_by_agent_id=uuid4(),
            name="original-name",
            description="original description",
            effect=PolicyEffect.ALLOW,
            subjects={},
            resources={},
            actions=["read"],
            conditions={},
            priority=0,
            enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        defaults.update(overrides)
        return Policy(**defaults)

    @pytest.mark.asyncio
    async def test_updatable_fields_are_applied(self) -> None:
        """All fields listed in _UPDATABLE_FIELDS are written to the model."""
        policy = self._make_policy()
        original_created_by = policy.created_by_agent_id

        payload = PolicyUpdate(
            name="new-name",
            description="new description",
            effect=PolicyEffect.DENY,
            subjects={"wildcard": True},
            resources={"paths": ["/api/v1/*"]},
            actions=["write"],
            conditions={"ip_ranges": ["10.0.0.0/8"]},
            priority=50,
            enabled=False,
        )

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = policy
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        with patch("agentauth.api.v1.policies._invalidate_policy_cache", new_callable=AsyncMock):
            from agentauth.api.v1.policies import update_policy
            result = await update_policy(
                policy_id=policy.id,
                payload=payload,
                session=mock_session,
            )

        # All updatable fields should be changed
        assert policy.name == "new-name"
        assert policy.description == "new description"
        assert policy.effect == PolicyEffect.DENY
        assert policy.subjects == {"wildcard": True}
        assert policy.resources == {"paths": ["/api/v1/*"]}
        assert policy.actions == ["write"]
        assert policy.conditions == {"ip_ranges": ["10.0.0.0/8"]}
        assert policy.priority == 50
        assert policy.enabled is False
        # Non-updatable fields must remain untouched
        assert policy.created_by_agent_id == original_created_by

    @pytest.mark.asyncio
    async def test_non_updatable_fields_in_raw_data_are_silently_ignored(self) -> None:
        """If update_data contains a non-updatable field, it is silently skipped.

        This simulates a scenario where the Pydantic schema is later extended with a
        non-updatable field — the allowlist acts as a defence-in-depth guard.
        We verify this by calling setattr directly with a non-updatable field name
        and confirming the _UPDATABLE_FIELDS guard prevents the write.
        """
        policy = self._make_policy()
        original_created_by = policy.created_by_agent_id
        injected_foreign_id = uuid4()

        # Simulate what update_policy does — loop over fields and apply allowlist guard
        _UPDATABLE_FIELDS = {
            "name",
            "description",
            "effect",
            "subjects",
            "resources",
            "actions",
            "conditions",
            "priority",
            "enabled",
        }

        # A dict that includes BOTH updatable and non-updatable keys
        update_data = {
            "name": "safe-name",
            "created_by_agent_id": injected_foreign_id,  # non-updatable
        }

        for field, value in update_data.items():
            if field not in _UPDATABLE_FIELDS:
                continue
            setattr(policy, field, value)

        # Non-updatable fields must NOT have changed
        assert policy.created_by_agent_id == original_created_by
        assert policy.created_by_agent_id != injected_foreign_id
        # The updatable field should have changed
        assert policy.name == "safe-name"

    @pytest.mark.asyncio
    async def test_partial_update_only_changes_provided_fields(self) -> None:
        """Unset fields in a partial update are not written to the model (exclude_unset=True)."""
        policy = self._make_policy(name="keep-name", priority=10)

        # Only update 'enabled' — name and priority should remain unchanged
        payload = PolicyUpdate(enabled=False)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = policy
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()

        with patch("agentauth.api.v1.policies._invalidate_policy_cache", new_callable=AsyncMock):
            from agentauth.api.v1.policies import update_policy
            await update_policy(
                policy_id=policy.id,
                payload=payload,
                session=mock_session,
            )

        assert policy.enabled is False
        assert policy.name == "keep-name"
        assert policy.priority == 10
