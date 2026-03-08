"""Integration tests for client_credentials grant type."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent, AgentStatus
from agentauth.models.audit import ActorType, EventOutcome
from agentauth.models.credential import CredentialType
from agentauth.models.signing_key import SigningKey
from agentauth.services.audit import AuditService
from agentauth.services.credential import CredentialService
from agentauth.services.crypto import CryptoService


@pytest.mark.asyncio
async def test_client_credentials_with_api_key(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test client_credentials grant with API key authentication."""
    # Setup: Create an API key with specific scopes
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read", "files.write", "email.send"],
    )
    await db_session.commit()

    # Make token request
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
            "scope": "files.read files.write",
        },
    )

    # Assert response
    assert response.status_code == 200
    data = response.json()

    # Verify token response structure
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] > 0
    assert data["scope"] == "files.read files.write"
    assert "issued_at" in data
    assert "expires_at" in data

    # Verify tokens are valid JWT strings
    assert len(data["access_token"].split(".")) == 3
    assert len(data["refresh_token"].split(".")) == 3

    # Verify audit event was recorded
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(
        event_type="token.issued",
        actor_id=root_agent.id,
    )
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.SUCCESS
    assert event.actor_id == root_agent.id
    assert event.event_metadata["grant_type"] == "client_credentials"
    assert set(event.event_metadata["scopes"]) == {"files.read", "files.write"}


@pytest.mark.asyncio
async def test_client_credentials_no_scope_grants_all(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that omitting scope grants all allowed scopes."""
    # Setup: Create credential with multiple scopes
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read", "files.write", "email.send"],
    )
    await db_session.commit()

    # Make token request without scope parameter
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )

    # Assert response
    assert response.status_code == 200
    data = response.json()

    # Verify all allowed scopes are granted
    granted_scopes = set(data["scope"].split())
    assert granted_scopes == {"files.read", "files.write", "email.send"}


@pytest.mark.asyncio
async def test_client_credentials_scope_validation_denies_escalation(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that requesting scopes beyond allowed scopes is denied."""
    # Setup: Create credential with limited scopes
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    # Attempt to request more scopes than allowed
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
            "scope": "files.read files.write admin.access",
        },
    )

    # Assert denied
    assert response.status_code == 400
    error = response.json()
    assert error["detail"]["error"] == "invalid_scope"

    # Verify audit event recorded the denial
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(
        event_type="token.issued",
        actor_id=root_agent.id,
    )
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.DENIED
    assert event.event_metadata["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_client_credentials_invalid_credential(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test authentication failure with invalid credential."""
    # Attempt with invalid API key
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": "invalid_api_key_12345",
        },
    )

    # Assert unauthorized
    assert response.status_code == 401
    error = response.json()
    assert error["detail"]["error"] == "invalid_client"

    # Verify audit event recorded the failure
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(event_type="token.issued")
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.FAILURE
    assert event.event_metadata["error"] == "invalid_credential"


@pytest.mark.asyncio
async def test_client_credentials_missing_secret(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test request fails when client_secret is missing."""
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
        },
    )

    # Assert bad request
    assert response.status_code == 400
    error = response.json()
    assert error["detail"]["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_client_credentials_inactive_agent(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that inactive agent cannot get token."""
    # Setup: Create credential
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )

    # Deactivate agent
    root_agent.deactivate()
    await db_session.commit()

    # Attempt to get token
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )

    # Assert unauthorized
    assert response.status_code == 401
    error = response.json()
    assert error["detail"]["error"] == "invalid_client"

    # Verify audit event
    audit_service = AuditService(db_session)
    events = await audit_service.get_events(
        event_type="token.issued",
        actor_id=root_agent.id,
    )
    assert len(events) > 0
    event = events[0]
    assert event.outcome == EventOutcome.DENIED
    assert event.event_metadata["error"] == "agent_not_active"


@pytest.mark.asyncio
async def test_client_credentials_revoked_credential(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that revoked credential cannot be used."""
    # Setup: Create and revoke credential
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await credential_service.revoke_credential(credential.id)
    await db_session.commit()

    # Attempt to use revoked credential
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )

    # Assert unauthorized
    assert response.status_code == 401
    error = response.json()
    assert error["detail"]["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_client_credentials_with_client_secret_type(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test client_credentials with CLIENT_SECRET credential type."""
    # Setup: Create client secret credential
    credential_service = CredentialService(db_session)
    credential, client_secret = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.CLIENT_SECRET,
        scopes=["api.access"],
    )
    await db_session.commit()

    # Make token request
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": str(root_agent.id),
            "client_secret": client_secret,
        },
    )

    # Assert success
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["scope"] == "api.access"


@pytest.mark.asyncio
async def test_client_credentials_unsupported_grant_type(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test that unsupported grant types are rejected."""
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": "fake_code",
        },
    )

    # Assert bad request
    assert response.status_code == 400
    error = response.json()
    assert error["detail"]["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_client_credentials_token_structure_and_claims(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that issued tokens have correct structure and claims."""
    # Setup: Create credential and get signing keys
    credential_service = CredentialService(db_session)
    crypto_service = CryptoService(db_session)

    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read", "files.write"],
    )
    await db_session.commit()

    # Get token
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
            "scope": "files.read",
        },
    )

    assert response.status_code == 200
    data = response.json()

    # Validate token using TokenService
    from agentauth.services.token import TokenService

    token_service = TokenService(db_session)

    # Validate access token
    validation_result = await token_service.validate_token(
        data["access_token"],
        expected_token_type="access",
    )

    assert validation_result.valid is True
    assert validation_result.claims is not None

    claims = validation_result.claims
    assert claims.sub == str(root_agent.id)
    assert claims.agent_type == root_agent.agent_type
    assert claims.trust_level == root_agent.trust_level
    assert claims.scopes == ["files.read"]
    assert claims.token_type == "access"

    # Validate refresh token
    refresh_validation = await token_service.validate_token(
        data["refresh_token"],
        expected_token_type="refresh",
    )

    assert refresh_validation.valid is True
    assert refresh_validation.claims.token_type == "refresh"


@pytest.mark.asyncio
async def test_client_credentials_credential_last_used_updated(
    client: AsyncClient,
    db_session: AsyncSession,
    root_agent: Agent,
    signing_key_rsa: SigningKey,
) -> None:
    """Test that credential's last_used_at is updated on successful auth."""
    # Setup: Create credential
    credential_service = CredentialService(db_session)
    credential, api_key = await credential_service.create_credential(
        agent_id=root_agent.id,
        credential_type=CredentialType.API_KEY,
        scopes=["files.read"],
    )
    await db_session.commit()

    # Verify last_used_at is None initially
    assert credential.last_used_at is None

    # Make token request
    response = await client.post(
        "/api/v1/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_secret": api_key,
        },
    )

    assert response.status_code == 200

    # Refresh credential from DB
    await db_session.refresh(credential)

    # Verify last_used_at was updated
    assert credential.last_used_at is not None
