"""Integration tests for token introspection with real Redis."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.redis import get_redis_client
from agentauth.models.agent import Agent
from agentauth.models.credential import CredentialType
from agentauth.models.signing_key import SigningKey
from agentauth.services.credential import CredentialService


@pytest.mark.asyncio
async def test_introspection_caching_with_real_redis(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspection actually caches results in Redis."""
    # Setup: Get a valid access token
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]

    # Get Redis client
    redis_client = get_redis_client()
    await redis_client.connect()

    try:
        # First introspection - should cache
        response1 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert response1.status_code == 200
        data1 = response1.json()
        assert data1["active"] is True

        # Verify cache was written
        cache_key = f"introspection:{access_token[-32:]}"
        cached_data = await redis_client.get_json(cache_key)
        assert cached_data is not None
        assert cached_data["active"] is True
        assert cached_data["jti"] == data1["jti"]

        # Second introspection - should hit cache
        response2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert response2.status_code == 200
        data2 = response2.json()
        assert data2 == data1  # Should be identical

    finally:
        await redis_client.disconnect()


@pytest.mark.asyncio
async def test_token_revocation_with_real_redis(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test token revocation with real Redis."""
    # Setup: Get a valid access token
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    access_token = token_response.json()["access_token"]

    # Get Redis client
    redis_client = get_redis_client()
    await redis_client.connect()

    try:
        # Verify token is active
        response1 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert response1.json()["active"] is True

        # Revoke the token
        revoke_response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )
        assert revoke_response.status_code == 200

        # Verify token is now inactive
        response2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert response2.json()["active"] is False

        # Verify JTI is in revocation blocklist
        jti = response1.json()["jti"]
        revoked = await redis_client.exists(f"revoked:{jti}")
        assert revoked is True

    finally:
        await redis_client.disconnect()


@pytest.mark.asyncio
async def test_cache_ttl_matches_token_lifetime(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that cache TTL matches remaining token lifetime."""
    # Setup: Get a valid access token
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    access_token = token_response.json()["access_token"]
    expires_in = token_response.json()["expires_in"]

    # Get Redis client
    redis_client = get_redis_client()
    await redis_client.connect()

    try:
        # Introspect to cache
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert response.status_code == 200

        # Check TTL in Redis (using low-level client)
        cache_key = f"introspection:{access_token[-32:]}"
        if redis_client._client:
            ttl = await redis_client._client.ttl(cache_key)  # type: ignore

            # TTL should be roughly equal to expires_in (within 5 seconds tolerance)
            assert ttl > 0
            assert abs(ttl - expires_in) <= 5

    finally:
        await redis_client.disconnect()


@pytest.mark.asyncio
async def test_cascading_revocation_access_token_revokes_refresh(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that revoking an access token also revokes its refresh token."""
    # Setup: Get tokens
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    access_token = token_response.json()["access_token"]
    refresh_token = token_response.json()["refresh_token"]

    # Get Redis client
    redis_client = get_redis_client()
    await redis_client.connect()

    try:
        # Verify both tokens are active
        access_introspect = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert access_introspect.json()["active"] is True

        refresh_introspect = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert refresh_introspect.json()["active"] is True

        # Revoke the access token
        revoke_response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )
        assert revoke_response.status_code == 200

        # Verify both tokens are now inactive (cascading revocation)
        access_introspect2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert access_introspect2.json()["active"] is False

        refresh_introspect2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert refresh_introspect2.json()["active"] is False

    finally:
        await redis_client.disconnect()


@pytest.mark.asyncio
async def test_cascading_revocation_refresh_token_revokes_access(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that revoking a refresh token also revokes its access token."""
    # Setup: Get tokens
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    access_token = token_response.json()["access_token"]
    refresh_token = token_response.json()["refresh_token"]

    # Get Redis client
    redis_client = get_redis_client()
    await redis_client.connect()

    try:
        # Verify both tokens are active
        access_introspect = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert access_introspect.json()["active"] is True

        refresh_introspect = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert refresh_introspect.json()["active"] is True

        # Revoke the refresh token
        revoke_response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": refresh_token},
        )
        assert revoke_response.status_code == 200

        # Verify both tokens are now inactive (cascading revocation)
        access_introspect2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert access_introspect2.json()["active"] is False

        refresh_introspect2 = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert refresh_introspect2.json()["active"] is False

    finally:
        await redis_client.disconnect()
