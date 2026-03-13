"""Integration tests for cascading token revocation.

Task 7.2 — verifies that:
1. All token issuance paths write token_pair metadata to Redis.
2. Revoking an access token also revokes the paired refresh token.
3. Revoking a refresh token also revokes the paired access token.
4. The revoked refresh token cannot be used to obtain new tokens.
5. Missing pair metadata in Redis does not cause revocation to error.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.services.credential import CredentialService
from agentauth.services.token import TokenService


async def _mint_tokens(db_session: AsyncSession, agent: Agent) -> tuple[str, str]:
    """Mint an access+refresh token pair via TokenService and return (access, refresh)."""
    service = TokenService(db_session)
    response = await service.mint_token(agent=agent, scopes=["api.read"])
    assert response.refresh_token is not None, "mint_token must return a refresh token"
    return response.access_token, response.refresh_token


@pytest.mark.asyncio
class TestTokenPairMetadata:
    """All issuance paths must write token_pair metadata to Redis."""

    async def test_mint_token_writes_pair_metadata(
        self, db_session: AsyncSession, root_agent: Agent, signing_key_rsa: object
    ) -> None:
        """mint_token with token_type='access' stores token_pair keys in Redis."""
        from agentauth.core.redis import get_redis_client
        import jwt as _jwt

        service = TokenService(db_session)
        token_response = await service.mint_token(agent=root_agent, scopes=["api.read"])

        access_token = token_response.access_token
        refresh_token = token_response.refresh_token
        assert refresh_token is not None

        access_jti = _jwt.decode(access_token, options={"verify_signature": False})["jti"]
        refresh_jti = _jwt.decode(refresh_token, options={"verify_signature": False})["jti"]

        redis_client = get_redis_client()
        # Both pair mapping keys must exist
        access_pair = await redis_client.get(f"token_pair:access:{access_jti}")
        refresh_pair = await redis_client.get(f"token_pair:refresh:{refresh_jti}")

        assert access_pair is not None, "token_pair:access:{jti} missing from Redis"
        assert refresh_pair is not None, "token_pair:refresh:{jti} missing from Redis"
        assert access_pair == refresh_jti
        assert refresh_pair == access_jti

    async def test_client_credentials_grant_writes_pair_metadata(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """client_credentials grant writes token_pair metadata."""
        import jwt as _jwt
        from agentauth.core.redis import get_redis_client

        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data.get("refresh_token") is not None

        access_jti = _jwt.decode(data["access_token"], options={"verify_signature": False})["jti"]
        refresh_jti = _jwt.decode(data["refresh_token"], options={"verify_signature": False})["jti"]

        redis_client = get_redis_client()
        access_pair = await redis_client.get(f"token_pair:access:{access_jti}")
        refresh_pair = await redis_client.get(f"token_pair:refresh:{refresh_jti}")

        assert access_pair == refresh_jti
        assert refresh_pair == access_jti

    async def test_refresh_token_grant_writes_pair_metadata(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """refresh_token grant writes token_pair metadata for the NEW token pair."""
        import jwt as _jwt
        from agentauth.core.redis import get_redis_client

        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        # First issue tokens via client_credentials
        token_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        assert token_resp.status_code == 200
        old_refresh = token_resp.json()["refresh_token"]

        # Refresh
        refresh_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "refresh_token", "refresh_token": old_refresh},
        )
        assert refresh_resp.status_code == 200, refresh_resp.text
        new_data = refresh_resp.json()
        assert new_data.get("refresh_token") is not None

        new_access_jti = _jwt.decode(
            new_data["access_token"], options={"verify_signature": False}
        )["jti"]
        new_refresh_jti = _jwt.decode(
            new_data["refresh_token"], options={"verify_signature": False}
        )["jti"]

        redis_client = get_redis_client()
        assert await redis_client.get(f"token_pair:access:{new_access_jti}") == new_refresh_jti
        assert await redis_client.get(f"token_pair:refresh:{new_refresh_jti}") == new_access_jti


@pytest.mark.asyncio
class TestCascadingRevocation:
    """Revoking one token in a pair must revoke the other."""

    async def test_revoke_access_token_also_revokes_refresh_token(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """Revoking an access token cascades to the paired refresh token."""
        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        token_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        assert token_resp.status_code == 200
        access_token = token_resp.json()["access_token"]
        refresh_token = token_resp.json()["refresh_token"]

        # Revoke the access token
        revoke_resp = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token, "token_type_hint": "access_token"},
        )
        assert revoke_resp.status_code == 200

        # Access token must now be inactive
        intro_access = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert intro_access.json()["active"] is False

        # Refresh token must ALSO be inactive (cascading revocation)
        intro_refresh = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert intro_refresh.json()["active"] is False

    async def test_revoked_access_token_paired_refresh_cannot_mint_new_tokens(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """A refresh token paired with a revoked access token cannot obtain new tokens."""
        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        token_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        access_token = token_resp.json()["access_token"]
        refresh_token = token_resp.json()["refresh_token"]

        # Revoke the access token (cascade should revoke the refresh too)
        await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )

        # Attempt to use the now-revoked refresh token
        refresh_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        # Should fail — either 401 (revoked/replay) or 401 (invalid)
        assert refresh_resp.status_code == 401

    async def test_revoke_refresh_token_also_revokes_access_token(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """Revoking a refresh token cascades to the paired access token."""
        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        token_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        access_token = token_resp.json()["access_token"]
        refresh_token = token_resp.json()["refresh_token"]

        # Revoke the refresh token
        revoke_resp = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": refresh_token, "token_type_hint": "refresh_token"},
        )
        assert revoke_resp.status_code == 200

        # Refresh token must be inactive
        intro_refresh = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": refresh_token},
        )
        assert intro_refresh.json()["active"] is False

        # Access token must ALSO be inactive (cascading revocation)
        intro_access = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert intro_access.json()["active"] is False

    async def test_revocation_with_missing_pair_metadata_does_not_error(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        auth_agent: Agent,
        signing_key_rsa: object,
    ) -> None:
        """Revoking a token whose pair metadata was lost in Redis succeeds without error."""
        import jwt as _jwt
        from agentauth.core.redis import get_redis_client

        credential_service = CredentialService(db_session)
        _, raw_key = await credential_service.create_credential(
            agent_id=auth_agent.id, scopes=["api.read"]
        )
        await db_session.commit()

        token_resp = await client.post(
            "/api/v1/auth/token",
            json={"grant_type": "client_credentials", "client_secret": raw_key},
        )
        access_token = token_resp.json()["access_token"]

        # Simulate Redis pair metadata being lost
        access_jti = _jwt.decode(access_token, options={"verify_signature": False})["jti"]
        redis_client = get_redis_client()
        await redis_client.delete(f"token_pair:access:{access_jti}")

        # Revocation should still succeed (idempotent, no error)
        revoke_resp = await client.post(
            "/api/v1/auth/token/revoke",
            data={"token": access_token},
        )
        assert revoke_resp.status_code == 200

        # The access token itself should be inactive
        intro = await client.post(
            "/api/v1/auth/token/introspect",
            data={"token": access_token},
        )
        assert intro.json()["active"] is False
