"""Unit tests for token introspection in TokenService."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.signing_key import SigningKey
from agentauth.services.token import TokenService


@pytest.mark.asyncio
async def test_introspect_valid_token(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of a valid token."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read", "files.write"],
        token_type="access",
    )

    # Introspect the token (disable cache for unit test)
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(
            token_response.access_token,
            use_cache=True,
        )

    # Verify response structure
    assert result["active"] is True
    assert result["scope"] == "files.read files.write"
    assert result["client_id"] == str(root_agent.id)
    assert result["username"] == str(root_agent.id)
    assert result["token_type"] == "access"
    assert result["sub"] == str(root_agent.id)
    assert result["iss"] is not None
    assert result["jti"] is not None
    assert "exp" in result
    assert "iat" in result
    assert result["agent_type"] == root_agent.agent_type.value
    assert result["trust_level"] == root_agent.trust_level.value
    assert result["parent_agent_id"] is None  # root agent


@pytest.mark.asyncio
async def test_introspect_invalid_token(
    db_session: AsyncSession,
) -> None:
    """Test introspection of an invalid token."""
    token_service = TokenService(db_session)

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token("invalid.token.here")

    # Should return inactive
    assert result["active"] is False
    assert "scope" not in result or result["scope"] is None


@pytest.mark.asyncio
async def test_introspect_expired_token(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of an expired token."""
    token_service = TokenService(db_session)

    # Mint a token with very short expiration
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
        expires_in_minutes=-1,  # Already expired
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(token_response.access_token)

    # Should return inactive for expired token
    assert result["active"] is False


@pytest.mark.asyncio
async def test_introspect_revoked_token(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of a revoked token."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = True  # Token is in revocation blocklist
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(token_response.access_token)

    # Should return inactive for revoked token
    assert result["active"] is False


@pytest.mark.asyncio
async def test_introspect_uses_cache(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspection uses Redis cache."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    cached_response = {
        "active": True,
        "scope": "files.read",
        "client_id": str(root_agent.id),
        "jti": "cached-jti",
    }

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = cached_response
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(
            token_response.access_token,
            use_cache=True,
        )

    # Should return cached result
    assert result == cached_response
    assert result["jti"] == "cached-jti"


@pytest.mark.asyncio
async def test_introspect_caches_result(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspection caches valid results."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
        expires_in_minutes=15,
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(
            token_response.access_token,
            use_cache=True,
        )

        # Verify cache was written
        mock_client.set_json.assert_called_once()
        call_args = mock_client.set_json.call_args
        cache_key = call_args[0][0]
        cached_data = call_args[0][1]
        ttl = call_args[1]["ex"]

        assert cache_key.startswith("introspection:")
        assert cached_data["active"] is True
        assert cached_data["jti"] == result["jti"]
        assert ttl > 0
        assert ttl <= 15 * 60  # Should be <= 15 minutes


@pytest.mark.asyncio
async def test_introspect_skip_cache(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection with cache disabled."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = {"active": True, "cached": True}
        mock_client.exists.return_value = False  # Not revoked
        mock_redis.return_value = mock_client

        result = await token_service.introspect_token(
            token_response.access_token,
            use_cache=False,
        )

    # Should not use cache
    assert result["active"] is True
    assert "cached" not in result  # Should have validated token, not used cache


@pytest.mark.asyncio
async def test_revoke_token(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test token revocation."""
    token_service = TokenService(db_session)

    # Mint a token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.set.return_value = True
        mock_client.delete.return_value = True
        mock_client.get = AsyncMock(return_value=None)  # No paired token in Redis
        mock_redis.return_value = mock_client

        # Revoke the token
        revoked = await token_service.revoke_token(token_response.access_token)

    assert revoked is True

    # Verify calls to Redis
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_redis.return_value = mock_client
        mock_client.set.assert_called_once()
        mock_client.delete.assert_called_once()

        # Verify the JTI was added to revocation blocklist
        set_call_args = mock_client.set.call_args
        key = set_call_args[0][0]
        assert key.startswith("revoked:")


@pytest.mark.asyncio
async def test_revoke_expired_token(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test revocation of already expired token."""
    token_service = TokenService(db_session)

    # Mint an expired token
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
        expires_in_minutes=-5,  # Expired 5 minutes ago
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.set.return_value = True
        mock_redis.return_value = mock_client

        # Try to revoke the expired token
        revoked = await token_service.revoke_token(token_response.access_token)

    # Should succeed but not add to blocklist (already expired)
    assert revoked is True


@pytest.mark.asyncio
async def test_revoke_invalid_token(
    db_session: AsyncSession,
) -> None:
    """Test revocation of invalid token."""
    token_service = TokenService(db_session)

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_redis.return_value = mock_client

        # Try to revoke invalid token
        revoked = await token_service.revoke_token("invalid.token.here")

    # Should fail gracefully
    assert revoked is False
