"""Integration tests for the refresh token flow (Task 2.6)."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.signing_key import SigningKey
from agentauth.services.token import TokenService
from agentauth.core.exceptions import TokenError


@pytest.mark.asyncio
class TestRefreshTokenFlow:
    """Tests for the refresh_token grant type and token rotation."""

    async def test_refresh_token_issues_new_pair(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Normal refresh flow: new access + refresh token pair issued."""
        token_service = TokenService(db_session)

        # Issue initial token pair
        initial = await token_service.mint_token(
            agent=root_agent,
            scopes=["api.read", "api.write"],
        )
        assert initial.refresh_token is not None

        # Exchange refresh token for new pair
        refreshed = await token_service.refresh_token_grant(initial.refresh_token)

        assert refreshed.access_token is not None
        assert refreshed.refresh_token is not None
        # New tokens must differ from the originals
        assert refreshed.access_token != initial.access_token
        assert refreshed.refresh_token != initial.refresh_token

    async def test_refresh_preserves_scopes(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Refreshed token carries the same scopes as the original."""
        import jwt as pyjwt

        token_service = TokenService(db_session)
        original_scopes = ["files.read", "email.send"]

        initial = await token_service.mint_token(
            agent=root_agent,
            scopes=original_scopes,
        )
        assert initial.refresh_token is not None

        refreshed = await token_service.refresh_token_grant(initial.refresh_token)

        decoded = pyjwt.decode(
            refreshed.access_token,
            options={"verify_signature": False},
        )
        assert decoded["scopes"] == original_scopes

    async def test_old_refresh_token_revoked_after_use(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Old refresh token must be invalid after a successful refresh."""
        from agentauth.core.redis import get_redis_client
        import jwt as pyjwt

        token_service = TokenService(db_session)

        initial = await token_service.mint_token(agent=root_agent, scopes=["api.read"])
        assert initial.refresh_token is not None

        old_refresh_token = initial.refresh_token
        await token_service.refresh_token_grant(old_refresh_token)

        # Old refresh JTI should now be in the revocation blocklist
        redis_client = get_redis_client()
        old_jti = pyjwt.decode(old_refresh_token, options={"verify_signature": False})["jti"]
        is_revoked = await redis_client.exists(f"revoked:{old_jti}")
        assert is_revoked, "Old refresh token must be revoked after use"

    async def test_replay_attack_detected(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Using a refresh token twice raises TokenError (replay attack)."""
        token_service = TokenService(db_session)

        initial = await token_service.mint_token(agent=root_agent, scopes=["api.read"])
        assert initial.refresh_token is not None

        # First use — should succeed
        await token_service.refresh_token_grant(initial.refresh_token)

        # Second use with the same token — must raise TokenError
        with pytest.raises(TokenError, match="reuse detected"):
            await token_service.refresh_token_grant(initial.refresh_token)

    async def test_replay_revokes_access_token_family(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """On replay, the linked access token is also revoked."""
        from agentauth.core.redis import get_redis_client
        import jwt as pyjwt

        token_service = TokenService(db_session)

        initial = await token_service.mint_token(agent=root_agent, scopes=["api.read"])
        assert initial.refresh_token is not None

        # Consume the refresh token legitimately
        await token_service.refresh_token_grant(initial.refresh_token)

        # Replay the same refresh token — triggers family revocation
        refresh_claims = pyjwt.decode(
            initial.refresh_token, options={"verify_signature": False}
        )
        access_jti = refresh_claims.get("access_token_jti")
        assert access_jti is not None

        with pytest.raises(TokenError):
            await token_service.refresh_token_grant(initial.refresh_token)

        # The original access token must also be revoked
        redis_client = get_redis_client()
        is_revoked = await redis_client.exists(f"revoked:{access_jti}")
        assert is_revoked, "Access token must be revoked when token family is compromised"

    async def test_invalid_refresh_token_rejected(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Garbage tokens raise TokenError."""
        token_service = TokenService(db_session)

        with pytest.raises(TokenError):
            await token_service.refresh_token_grant("not.a.valid.jwt")

    async def test_access_token_cannot_be_used_as_refresh(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        signing_key_rsa: SigningKey,
    ) -> None:
        """Passing an access token to refresh_token_grant must be rejected."""
        token_service = TokenService(db_session)

        initial = await token_service.mint_token(agent=root_agent, scopes=["api.read"])

        with pytest.raises(TokenError, match="not a refresh token"):
            await token_service.refresh_token_grant(initial.access_token)
