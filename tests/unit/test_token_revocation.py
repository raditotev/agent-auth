"""Tests for token revocation with Lua script and pipeline optimizations."""

import hashlib
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from agentauth.services.token import TokenService


def _make_token(
    jti: str = "test-jti-123",
    token_type: str = "access",
    exp_seconds: int = 900,
    sub: str = "agent-id",
) -> str:
    """Create a test JWT token (unsigned)."""
    now = datetime.now(UTC)
    payload = {
        "jti": jti,
        "token_type": token_type,
        "sub": sub,
        "exp": int((now + timedelta(seconds=exp_seconds)).timestamp()),
        "iat": int(now.timestamp()),
    }
    return jwt.encode(payload, "secret", algorithm="HS256")


@pytest.fixture
def mock_redis():
    """Create a mock Redis client with eval_script and pipeline support."""
    client = AsyncMock()
    client.eval_script = AsyncMock()
    # Pipeline context manager returns an async mock
    pipe = AsyncMock()
    pipe.delete = MagicMock()
    pipe.execute = AsyncMock(return_value=[1, 1])
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)
    client.pipeline = MagicMock(return_value=pipe)
    return client, pipe


@pytest.fixture
def token_service():
    """Create a token service with a mocked DB session."""
    session = AsyncMock()
    return TokenService(session)


class TestTokenRevocationLuaScript:
    """Tests verifying revoke_token uses Lua script instead of individual Redis calls."""

    @pytest.mark.asyncio
    async def test_revoke_uses_eval_script(self, token_service, mock_redis):
        """Verify revoke_token calls eval_script (Lua) instead of individual SET/GET/DELETE."""
        redis_client, pipe = mock_redis
        # No paired token
        redis_client.eval_script.return_value = [False, False, False]

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        redis_client.eval_script.assert_called_once()
        # Verify the Lua script is the class-level _REVOKE_LUA
        call_args = redis_client.eval_script.call_args
        assert "redis.call('SET', KEYS[1]" in call_args.kwargs.get("script", call_args[0][0])

    @pytest.mark.asyncio
    async def test_revoke_passes_correct_keys(self, token_service, mock_redis):
        """Verify the correct Redis keys are passed to the Lua script."""
        redis_client, pipe = mock_redis
        redis_client.eval_script.return_value = [False, False, False]

        jti = "my-jti-abc"
        token = _make_token(jti=jti, token_type="access")
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            await token_service.revoke_token(token)

        call_args = redis_client.eval_script.call_args
        keys = call_args.kwargs.get("keys", call_args[1] if len(call_args) > 1 else call_args[0][1])
        assert keys == [f"revoked:{jti}", f"introspection:{token_hash}", f"token_pair:access:{jti}"]

    @pytest.mark.asyncio
    async def test_revoke_no_individual_set_get_calls(self, token_service, mock_redis):
        """Ensure no individual SET/GET/EXISTS/DELETE calls are made for the main revocation."""
        redis_client, pipe = mock_redis
        redis_client.eval_script.return_value = [False, False, False]

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            await token_service.revoke_token(token)

        # The main revocation should NOT use individual set/get/exists/delete calls
        redis_client.set.assert_not_called()
        redis_client.get.assert_not_called()
        redis_client.exists.assert_not_called()
        redis_client.delete.assert_not_called()


class TestCascadingRevocation:
    """Tests verifying cascading revocation still works correctly with Lua script."""

    @pytest.mark.asyncio
    async def test_cascade_revokes_paired_refresh_token(self, token_service, mock_redis):
        """When revoking access token, paired refresh token should be revoked via Lua."""
        redis_client, pipe = mock_redis
        paired_jti = "paired-refresh-jti"
        # Lua returns: [paired_jti, paired_cache_key, already_revoked]
        redis_client.eval_script.return_value = [paired_jti, "", "0"]

        token = _make_token(token_type="access")

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        # Pipeline should clean up pair mappings
        redis_client.pipeline.assert_called_once()
        pipe.delete.assert_any_call("token_pair:access:test-jti-123")
        pipe.delete.assert_any_call(f"token_pair:refresh:{paired_jti}")
        pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cascade_revokes_paired_access_token(self, token_service, mock_redis):
        """When revoking refresh token, paired access token should be revoked via Lua."""
        redis_client, pipe = mock_redis
        paired_jti = "paired-access-jti"
        redis_client.eval_script.return_value = [paired_jti, "", "0"]

        token = _make_token(jti="refresh-jti", token_type="refresh")

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        pipe.delete.assert_any_call("token_pair:refresh:refresh-jti")
        pipe.delete.assert_any_call(f"token_pair:access:{paired_jti}")

    @pytest.mark.asyncio
    async def test_no_cascade_when_no_paired_token(self, token_service, mock_redis):
        """When there's no paired token, pipeline cleanup should not run."""
        redis_client, pipe = mock_redis
        redis_client.eval_script.return_value = [False, False, False]

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        redis_client.pipeline.assert_not_called()

    @pytest.mark.asyncio
    async def test_cascade_with_paired_cache_key(self, token_service, mock_redis):
        """Lua script should invalidate paired token's introspection cache."""
        redis_client, pipe = mock_redis
        paired_jti = "paired-jti"
        paired_cache_key = "introspection:abc123"
        redis_client.eval_script.return_value = [paired_jti, paired_cache_key, "0"]

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        # The cache invalidation happens inside Lua, so we just verify no crash
        redis_client.eval_script.assert_called_once()


class TestRevocationAlreadyRevoked:
    """Tests for handling already-revoked paired tokens."""

    @pytest.mark.asyncio
    async def test_already_revoked_paired_token_handled(self, token_service, mock_redis):
        """When paired token is already revoked, Lua script handles it gracefully."""
        redis_client, pipe = mock_redis
        paired_jti = "already-revoked-jti"
        # already_revoked = "1" means the paired token was already in blocklist
        redis_client.eval_script.return_value = [paired_jti, "", "1"]

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        # Pipeline cleanup should still happen for pair mappings
        redis_client.pipeline.assert_called_once()


class TestRevocationErrorHandling:
    """Tests verifying error handling doesn't crash on Redis failures."""

    @pytest.mark.asyncio
    async def test_redis_eval_failure_returns_false(self, token_service, mock_redis):
        """Redis eval_script failure should return False, not crash."""
        redis_client, pipe = mock_redis
        redis_client.eval_script.side_effect = ConnectionError("Redis down")

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is False

    @pytest.mark.asyncio
    async def test_pipeline_failure_doesnt_crash(self, token_service, mock_redis):
        """Pipeline failure during cleanup should not crash revocation."""
        redis_client, pipe = mock_redis
        redis_client.eval_script.return_value = ["paired-jti", "", "0"]
        pipe.execute.side_effect = ConnectionError("Redis pipeline failed")

        token = _make_token()

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            # Should not raise — _cleanup_pair_mappings catches exceptions
            result = await token_service.revoke_token(token)

        assert result is True

    @pytest.mark.asyncio
    async def test_expired_token_returns_true(self, token_service, mock_redis):
        """Expired token should return True without calling Redis."""
        redis_client, pipe = mock_redis
        token = _make_token(exp_seconds=-100)

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is True
        redis_client.eval_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_token_missing_jti_returns_false(self, token_service, mock_redis):
        """Token without JTI claim should return False."""
        redis_client, pipe = mock_redis
        payload = {"exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())}
        token = jwt.encode(payload, "secret", algorithm="HS256")

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token(token)

        assert result is False
        redis_client.eval_script.assert_not_called()

    @pytest.mark.asyncio
    async def test_invalid_token_returns_false(self, token_service, mock_redis):
        """Completely invalid token string should return False."""
        redis_client, pipe = mock_redis

        with patch("agentauth.services.token.get_redis_client", return_value=redis_client):
            result = await token_service.revoke_token("not-a-valid-jwt")

        assert result is False
