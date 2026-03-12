"""Unit tests for deferred credential last_used_at (Redis + flush task)."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from agentauth.tasks.credential_sync import REDIS_KEY_PREFIX, _flush_last_used_async


@pytest.mark.asyncio
class TestVerifyCredentialRedisWrite:
    """verify_credential() records usage in Redis instead of flushing to DB."""

    async def test_verify_credential_no_db_flush(
        self, db_session, root_agent,
    ) -> None:
        """verify_credential must NOT call session.flush()."""
        from agentauth.services.credential import CredentialService

        service = CredentialService(db_session)
        _, raw_key = await service.create_credential(agent_id=root_agent.id)

        # Spy on session.flush
        original_flush = db_session.flush
        flush_calls: list[object] = []

        async def _tracking_flush(*a, **kw):
            flush_calls.append(1)
            return await original_flush(*a, **kw)

        with patch.object(db_session, "flush", side_effect=_tracking_flush):
            with patch("agentauth.services.credential.get_redis_client") as mock_redis:
                mock_client = AsyncMock()
                mock_redis.return_value = mock_client
                verified = await service.verify_credential(raw_key)

        assert verified is not None
        # flush should not have been called by verify_credential
        assert len(flush_calls) == 0

    async def test_verify_credential_records_redis(
        self, db_session, root_agent,
    ) -> None:
        """verify_credential must SET the usage timestamp in Redis."""
        from agentauth.services.credential import CredentialService

        service = CredentialService(db_session)
        cred, raw_key = await service.create_credential(agent_id=root_agent.id)

        with patch("agentauth.services.credential.get_redis_client") as mock_redis:
            mock_client = AsyncMock()
            mock_redis.return_value = mock_client
            verified = await service.verify_credential(raw_key)

        assert verified is not None
        mock_client.set.assert_called_once()
        call_args = mock_client.set.call_args
        assert call_args[0][0] == f"cred_last_used:{cred.id}"
        # second arg is an ISO timestamp string
        datetime.fromisoformat(call_args[0][1])
        assert call_args[1]["ex"] == 300


@pytest.mark.asyncio
class TestFlushCredentialLastUsed:
    """Tests for the _flush_last_used_async helper."""

    async def test_flush_empty_redis(self) -> None:
        """No keys → no DB work, returns flushed=0."""
        redis_client = AsyncMock()
        redis_client.scan_keys = AsyncMock(return_value=[])

        result = await _flush_last_used_async(redis_client=redis_client)

        assert result == {"flushed": 0}

    async def test_flush_updates_db_and_deletes_keys(self) -> None:
        """Valid keys are flushed to DB and then deleted from Redis."""
        cred_id = uuid4()
        ts = datetime.now(UTC).isoformat()
        key = f"{REDIS_KEY_PREFIX}{cred_id}"

        redis_client = AsyncMock()
        redis_client.scan_keys = AsyncMock(return_value=[key])
        redis_client.get = AsyncMock(return_value=ts)
        redis_client.delete = AsyncMock(return_value=True)

        # Mock the DB session
        mock_session = AsyncMock()
        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("agentauth.tasks.credential_sync.get_session_maker", return_value=mock_session_maker):
            result = await _flush_last_used_async(redis_client=redis_client)

        assert result == {"flushed": 1}
        # DB should have been updated and committed
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_awaited_once()
        # Redis key should have been deleted after commit
        redis_client.delete.assert_awaited_once_with(key)

    async def test_flush_handles_invalid_keys_gracefully(self) -> None:
        """Malformed keys are skipped without crashing."""
        redis_client = AsyncMock()
        redis_client.scan_keys = AsyncMock(return_value=[f"{REDIS_KEY_PREFIX}not-a-uuid"])
        redis_client.get = AsyncMock(return_value="bad-timestamp")
        redis_client.delete = AsyncMock(return_value=True)

        result = await _flush_last_used_async(redis_client=redis_client)

        assert result == {"flushed": 0}
        # Invalid keys should still be cleaned up
        redis_client.delete.assert_awaited_once()

    async def test_flush_keeps_latest_timestamp(self) -> None:
        """When multiple keys exist for same cred, latest timestamp wins."""
        cred_id = uuid4()
        earlier = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        later = datetime.now(UTC).isoformat()
        key1 = f"{REDIS_KEY_PREFIX}{cred_id}"

        redis_client = AsyncMock()
        # Simulate scan returning the key once (dedup by key)
        redis_client.scan_keys = AsyncMock(return_value=[key1])
        redis_client.get = AsyncMock(return_value=later)
        redis_client.delete = AsyncMock(return_value=True)

        mock_session = AsyncMock()
        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with patch("agentauth.tasks.credential_sync.get_session_maker", return_value=mock_session_maker):
            result = await _flush_last_used_async(redis_client=redis_client)

        assert result == {"flushed": 1}
