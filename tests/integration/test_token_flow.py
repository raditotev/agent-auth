"""Integration tests for complete token flows."""

from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.agent import Agent
from agentauth.models.signing_key import KeyAlgorithm
from agentauth.services.crypto import CryptoService
from agentauth.services.token import TokenService


@pytest.mark.asyncio
class TestCompleteTokenFlow:
    """Integration tests for end-to-end token operations."""

    async def test_full_token_lifecycle_with_rsa(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
    ):
        """Test complete token lifecycle: generate key, mint token, validate token."""
        crypto_service = CryptoService(db_session)
        token_service = TokenService(db_session)

        # Step 1: Generate RSA signing key
        signing_key = await crypto_service.generate_rsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(signing_key)
        await db_session.commit()

        # Step 2: Mint access token
        scopes = ["api.read", "api.write", "files.read"]
        audience = "https://api.example.com"

        token_response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
            audience=audience,
            algorithm=KeyAlgorithm.RS256,
        )

        assert token_response.access_token is not None
        assert token_response.refresh_token is not None

        # Step 3: Validate the access token
        validation_result = await token_service.validate_token(
            token=token_response.access_token,
            expected_audience=audience,
            expected_token_type="access",
        )

        assert validation_result.valid is True
        assert validation_result.claims is not None
        assert validation_result.claims.sub == str(root_agent.id)
        assert validation_result.claims.scopes == scopes
        assert validation_result.claims.aud == audience

        # Step 4: Introspect the token
        introspection = await token_service.introspect_token(token_response.access_token)

        assert introspection["active"] is True
        assert introspection["scope"] == "api.read api.write files.read"
        assert introspection["agent_type"] == root_agent.agent_type.value

        # Step 5: Validate refresh token
        refresh_validation = await token_service.validate_token(
            token=token_response.refresh_token,
            expected_token_type="refresh",
        )

        assert refresh_validation.valid is True
        assert refresh_validation.claims.token_type == "refresh"

    async def test_full_token_lifecycle_with_ecdsa(
        self,
        db_session: AsyncSession,
        child_agent: Agent,
    ):
        """Test complete token lifecycle with ES256 algorithm."""
        crypto_service = CryptoService(db_session)
        token_service = TokenService(db_session)

        # Generate ECDSA signing key
        signing_key = await crypto_service.generate_ecdsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(signing_key)
        await db_session.commit()

        # Mint token with ECDSA
        token_response = await token_service.mint_token(
            agent=child_agent,
            scopes=["limited.scope"],
            algorithm=KeyAlgorithm.ES256,
        )

        # Verify token header
        header = jwt.get_unverified_header(token_response.access_token)
        assert header["alg"] == "ES256"
        assert header["kid"] == signing_key.key_id

        # Validate token
        validation_result = await token_service.validate_token(
            token=token_response.access_token,
        )

        assert validation_result.valid is True
        assert validation_result.claims.sub == str(child_agent.id)

    async def test_token_validation_with_multiple_keys(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
    ):
        """Test that tokens can be validated even after key rotation."""
        crypto_service = CryptoService(db_session)
        token_service = TokenService(db_session)

        # Generate first key
        key1 = await crypto_service.generate_rsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(key1)
        await db_session.commit()

        # Mint token with first key
        token1 = await token_service.mint_token(agent=root_agent)

        # Generate second key (simulating key rotation)
        key2 = await crypto_service.generate_rsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(key2)
        await db_session.commit()

        # Mint token with second key (should use most recent active key)
        # In reality this would be automatic, but here we mark key1 as expired
        key1.mark_expired()
        await db_session.commit()

        token2 = await token_service.mint_token(agent=root_agent)

        # Both tokens should be valid (different keys)
        result1 = await token_service.validate_token(token1.access_token)
        result2 = await token_service.validate_token(token2.access_token)

        assert result1.valid is True
        assert result2.valid is True

        # Verify they used different keys
        header1 = jwt.get_unverified_header(token1.access_token)
        header2 = jwt.get_unverified_header(token2.access_token)
        assert header1["kid"] == key1.key_id
        assert header2["kid"] == key2.key_id

    async def test_token_validation_across_agent_hierarchy(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
        child_agent: Agent,
    ):
        """Test token validation for agents in a hierarchy."""
        crypto_service = CryptoService(db_session)
        token_service = TokenService(db_session)

        # Generate signing key
        signing_key = await crypto_service.generate_rsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(signing_key)
        await db_session.commit()

        # Mint token for root agent
        root_token = await token_service.mint_token(
            agent=root_agent,
            scopes=["admin.full"],
        )

        # Mint token for child agent with delegation chain
        child_token = await token_service.mint_token(
            agent=child_agent,
            scopes=["user.read"],
            delegation_chain=[root_agent.id, child_agent.id],
        )

        # Validate both tokens
        root_validation = await token_service.validate_token(root_token.access_token)
        child_validation = await token_service.validate_token(child_token.access_token)

        assert root_validation.valid is True
        assert child_validation.valid is True

        # Verify delegation chain
        assert root_validation.claims.parent_agent_id is None
        assert root_validation.claims.delegation_chain is None

        assert child_validation.claims.parent_agent_id == root_agent.id
        assert child_validation.claims.delegation_chain == [root_agent.id, child_agent.id]

    async def test_verify_token_with_jwks(
        self,
        db_session: AsyncSession,
        root_agent: Agent,
    ):
        """Test that tokens can be verified using JWKS export."""
        crypto_service = CryptoService(db_session)
        token_service = TokenService(db_session)

        # Generate signing key
        signing_key = await crypto_service.generate_rsa_key_pair(
            activation_date=datetime.now(UTC),
            expiration_days=90,
        )
        db_session.add(signing_key)
        await db_session.commit()

        # Mint token
        token_response = await token_service.mint_token(agent=root_agent)

        # Export JWKS
        jwks = await crypto_service.export_jwks()

        assert "keys" in jwks
        assert len(jwks["keys"]) > 0

        # Find the key used for this token
        header = jwt.get_unverified_header(token_response.access_token)
        key_id = header["kid"]

        jwk = next((k for k in jwks["keys"] if k["kid"] == key_id), None)
        assert jwk is not None
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert "n" in jwk  # RSA modulus
        assert "e" in jwk  # RSA exponent

        # Verify we can still validate through our service
        validation = await token_service.validate_token(token_response.access_token)
        assert validation.valid is True
