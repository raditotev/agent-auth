"""Tests for token validation revocation check and signing key caching."""

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.signing_key import SigningKey
from agentauth.services.token import TokenService


@pytest.mark.asyncio
async def test_validate_revoked_token_returns_invalid(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """A revoked token (jti in Redis blocklist) returns valid=False."""
    token_service = TokenService(db_session)

    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.services.token.get_redis_client") as mock_get_redis:
        mock_client = AsyncMock()
        # No signing key cache hit — fall through to DB
        mock_client.get_json.return_value = None
        mock_client.set_json.return_value = True
        # Token IS revoked
        mock_client.exists.return_value = True
        mock_get_redis.return_value = mock_client

        result = await token_service.validate_token(token_response.access_token)

    assert result.valid is False
    assert result.claims is None
    assert result.error == "Token has been revoked"
    # Verify revocation was checked with correct key pattern
    mock_client.exists.assert_called_once()
    call_arg = mock_client.exists.call_args[0][0]
    assert call_arg.startswith("revoked:")


@pytest.mark.asyncio
async def test_validate_non_revoked_token_succeeds(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """A non-revoked token still validates successfully."""
    token_service = TokenService(db_session)

    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.services.token.get_redis_client") as mock_get_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.set_json.return_value = True
        # Token is NOT revoked
        mock_client.exists.return_value = False
        mock_get_redis.return_value = mock_client

        result = await token_service.validate_token(token_response.access_token)

    assert result.valid is True
    assert result.claims is not None
    assert result.claims.sub == str(root_agent.id)
    assert result.error is None


@pytest.mark.asyncio
async def test_validate_signing_key_cache_hit_skips_db(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """When signing key is cached in Redis, the DB query is skipped."""
    token_service = TokenService(db_session)

    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    # Prepare the cached key data matching what would be stored
    cached_key_data = {
        "public_key_pem": signing_key_rsa.public_key_pem,
        "algorithm": signing_key_rsa.algorithm.value,
        "key_id": signing_key_rsa.key_id,
        "status": signing_key_rsa.status.value,
    }

    with (
        patch("agentauth.services.token.get_redis_client") as mock_get_redis,
        patch.object(
            token_service.crypto_service,
            "get_signing_key_by_id",
            new_callable=AsyncMock,
        ) as mock_db_call,
    ):
        mock_client = AsyncMock()
        # Return cached signing key data
        mock_client.get_json.return_value = cached_key_data
        mock_client.exists.return_value = False  # Not revoked
        mock_get_redis.return_value = mock_client

        result = await token_service.validate_token(token_response.access_token)

    assert result.valid is True
    assert result.claims is not None
    # DB should NOT have been called
    mock_db_call.assert_not_called()
    # set_json should NOT have been called for signing key cache (already cached)
    for call in mock_client.set_json.call_args_list:
        assert not call[0][0].startswith("signing_key_cache:")


@pytest.mark.asyncio
async def test_validate_signing_key_cache_miss_populates_cache(
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """When signing key is NOT in Redis cache, it's fetched from DB and cached."""
    token_service = TokenService(db_session)

    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
    )

    with patch("agentauth.services.token.get_redis_client") as mock_get_redis:
        mock_client = AsyncMock()
        # No cache hit for signing key
        mock_client.get_json.return_value = None
        mock_client.set_json.return_value = True
        mock_client.exists.return_value = False  # Not revoked
        mock_get_redis.return_value = mock_client

        result = await token_service.validate_token(token_response.access_token)

    assert result.valid is True
    assert result.claims is not None

    # Verify the signing key was cached in Redis
    set_json_calls = mock_client.set_json.call_args_list
    cache_call = [c for c in set_json_calls if c[0][0].startswith("signing_key_cache:")]
    assert len(cache_call) == 1

    cached_data = cache_call[0][0][1]
    assert cached_data["public_key_pem"] == signing_key_rsa.public_key_pem
    assert cached_data["algorithm"] == signing_key_rsa.algorithm.value
    assert cached_data["key_id"] == signing_key_rsa.key_id

    # Verify TTL is 600 seconds
    assert cache_call[0][1]["ex"] == 600
