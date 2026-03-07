"""Integration tests for token introspection endpoint."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.audit import EventOutcome
from agentauth.models.credential import CredentialType
from agentauth.models.signing_key import SigningKey
from agentauth.services.audit import AuditService
from agentauth.services.credential import CredentialService
from agentauth.services.token import TokenService


@pytest.mark.asyncio
async def test_introspect_valid_access_token(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of a valid access token."""
    # Setup: Get a valid access token
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read", "files.write"],
    )
    await db_session.commit()

    # Get access token
    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
            "scope": "files.read files.write",
        },
    )
    assert token_response.status_code == 200
    access_token = token_response.json()["access_token"]

    # Mock Redis to avoid dependency on Redis server
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        # Introspect the token
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )

    # Assert response
    assert response.status_code == 200
    data = response.json()

    # Verify RFC 7662 compliance
    assert data["active"] is True
    assert data["scope"] == "files.read files.write"
    assert data["client_id"] == str(root_agent.id)
    assert data["username"] == str(root_agent.id)
    assert data["token_type"] == "access"
    assert data["sub"] == str(root_agent.id)
    assert "exp" in data
    assert "iat" in data
    assert "jti" in data
    assert "iss" in data
    assert "aud" in data

    # Verify custom claims
    assert data["agent_type"] == root_agent.agent_type.value
    assert data["trust_level"] == root_agent.trust_level.value
    assert data["parent_agent_id"] is None

    # Verify audit event
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(event_type="token.introspected")
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.SUCCESS
    assert event.event_metadata["active"] is True


@pytest.mark.asyncio
async def test_introspect_valid_refresh_token(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of a valid refresh token."""
    # Setup: Get a valid refresh token
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    # Get tokens
    token_response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )
    assert token_response.status_code == 200
    refresh_token = token_response.json()["refresh_token"]

    # Mock Redis
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        # Introspect the refresh token
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={
                "token": refresh_token,
                "token_type_hint": "refresh_token",
            },
        )

    assert response.status_code == 200
    data = response.json()

    assert data["active"] is True
    assert data["token_type"] == "refresh"
    assert data["sub"] == str(root_agent.id)


@pytest.mark.asyncio
async def test_introspect_invalid_token(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test introspection of an invalid token."""
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": "invalid.token.here"},
        )

    assert response.status_code == 200  # RFC 7662: always return 200
    data = response.json()

    # Should return inactive
    assert data["active"] is False
    # Other fields should be None or absent
    assert data.get("scope") is None
    assert data.get("client_id") is None

    # Verify audit event
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(event_type="token.introspected")
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.FAILURE
    assert event.event_metadata["active"] is False


@pytest.mark.asyncio
async def test_introspect_expired_token(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of an expired token."""
    # Create an expired token using TokenService directly
    token_service = TokenService(db_session)
    token_response = await token_service.mint_token(
        agent=root_agent,
        scopes=["files.read"],
        token_type="access",
        expires_in_minutes=-10,  # Expired 10 minutes ago
    )

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": token_response.access_token},
        )

    assert response.status_code == 200
    data = response.json()

    # Expired token should be inactive
    assert data["active"] is False


@pytest.mark.asyncio
async def test_introspect_revoked_token(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection of a revoked token."""
    # Setup: Get a valid token
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

    # Mock Redis to simulate revoked token
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = True  # Token is revoked
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        # Introspect the revoked token
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )

    assert response.status_code == 200
    data = response.json()

    # Revoked token should be inactive
    assert data["active"] is False


@pytest.mark.asyncio
async def test_introspect_uses_cache(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspection uses and returns cached results."""
    # Setup: Get a valid token
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

    # Mock Redis with cached response
    cached_response = {
        "active": True,
        "scope": "files.read",
        "client_id": str(root_agent.id),
        "jti": "cached-jti-123",
    }

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = cached_response
        mock_redis.return_value = mock_client

        # Introspect the token
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )

    assert response.status_code == 200
    data = response.json()

    # Should return cached data
    assert data["active"] is True
    assert data["jti"] == "cached-jti-123"


@pytest.mark.asyncio
async def test_introspect_caches_new_result(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspection caches new results."""
    # Setup: Get a valid token
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

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None  # Cache miss
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        # Introspect the token
        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["active"] is True

    # Verify cache was written
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_redis.return_value = mock_client
        mock_client.set_json.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_token_endpoint(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test token revocation endpoint."""
    # Setup: Get a valid token
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

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.set.return_value = True
        mock_client.delete.return_value = True
        mock_redis.return_value = mock_client

        # Revoke the token
        response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )

    # RFC 7009: Should return 200 OK
    assert response.status_code == 200
    assert response.json() == {}

    # Verify audit event
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(event_type="token.revoked")
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.SUCCESS


@pytest.mark.asyncio
async def test_revoke_invalid_token_succeeds(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test that revoking invalid token succeeds (RFC 7009 idempotence)."""
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_redis.return_value = mock_client

        response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": "invalid.token.here"},
        )

    # RFC 7009: Should still return 200 OK (idempotent)
    assert response.status_code == 200
    assert response.json() == {}


@pytest.mark.asyncio
async def test_revoke_then_introspect_returns_inactive(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that introspecting a revoked token returns inactive."""
    # Setup: Get a valid token
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

    # Revoke the token
    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.set.return_value = True
        mock_client.delete.return_value = True
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_redis.return_value = mock_client

        revoke_response = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )
        assert revoke_response.status_code == 200

        # Now introspect - simulate revoked state
        mock_client.exists.return_value = True  # Now in blocklist
        introspect_response = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )

    assert introspect_response.status_code == 200
    data = introspect_response.json()
    assert data["active"] is False


@pytest.mark.asyncio
async def test_introspect_with_token_type_hint(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test introspection with token_type_hint parameter."""
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

    with patch("agentauth.core.redis.get_redis_client") as mock_redis:
        mock_client = AsyncMock()
        mock_client.get_json.return_value = None
        mock_client.exists.return_value = False
        mock_client.set_json.return_value = True
        mock_redis.return_value = mock_client

        response = await client.post(
            "/api/v1/auth/token/introspect",
            data={
                "token": access_token,
                "token_type_hint": "access_token",
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["active"] is True
    assert data["token_type"] == "access"
