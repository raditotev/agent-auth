"""Tests for token service."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.config import settings
from agentauth.core.exceptions import TokenError
from agentauth.models.agent import Agent, AgentType, TrustLevel
from agentauth.models.signing_key import KeyAlgorithm
from agentauth.schemas.token import TokenClaims
from agentauth.services.crypto import CryptoService
from agentauth.services.token import TokenService


@pytest.fixture
async def crypto_service(db_session: AsyncSession) -> CryptoService:
    """Create crypto service fixture."""
    return CryptoService(db_session)


@pytest.fixture
async def token_service(db_session: AsyncSession) -> TokenService:
    """Create token service fixture."""
    return TokenService(db_session)


@pytest.fixture
async def active_rsa_key(crypto_service: CryptoService, db_session: AsyncSession):
    """Create and persist an active RSA signing key."""
    key = await crypto_service.generate_rsa_key_pair(
        activation_date=datetime.now(UTC),
        expiration_days=90,
    )
    db_session.add(key)
    await db_session.commit()
    await db_session.refresh(key)
    return key


@pytest.fixture
async def active_ecdsa_key(crypto_service: CryptoService, db_session: AsyncSession):
    """Create and persist an active ECDSA signing key."""
    key = await crypto_service.generate_ecdsa_key_pair(
        activation_date=datetime.now(UTC),
        expiration_days=90,
    )
    db_session.add(key)
    await db_session.commit()
    await db_session.refresh(key)
    return key


class TestTokenMinting:
    """Tests for token minting functionality."""

    async def test_mint_access_token_success(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test successful access token minting."""
        scopes = ["files.read", "files.write"]
        audience = "https://api.example.com"

        response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
            audience=audience,
            token_type="access",
        )

        # Verify response structure
        assert response.access_token is not None
        assert response.refresh_token is not None  # Should include refresh token
        assert response.token_type == "Bearer"
        assert response.expires_in == settings.access_token_expire_minutes * 60
        assert response.scope == "files.read files.write"
        assert isinstance(response.issued_at, datetime)
        assert isinstance(response.expires_at, datetime)

        # Verify expiration times
        assert response.expires_at > response.issued_at
        expected_expires = response.issued_at + timedelta(minutes=settings.access_token_expire_minutes)
        assert abs((response.expires_at - expected_expires).total_seconds()) < 2

    async def test_mint_token_includes_all_claims(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that minted token includes all required claims."""
        scopes = ["api.read"]
        audience = "https://api.example.com"
        delegation_chain = [root_agent.id]

        response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
            audience=audience,
            delegation_chain=delegation_chain,
        )

        # Decode without verification to inspect claims
        decoded = jwt.decode(response.access_token, options={"verify_signature": False})

        # Verify standard JWT claims
        assert decoded["iss"] == settings.issuer_url
        assert decoded["sub"] == str(root_agent.id)
        assert decoded["aud"] == audience
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded

        # Verify custom AgentAuth claims
        assert decoded["scopes"] == scopes
        assert decoded["agent_type"] == root_agent.agent_type.value
        assert decoded["trust_level"] == root_agent.trust_level.value
        assert decoded["parent_agent_id"] is None  # Root agent has no parent
        assert decoded["delegation_chain"] == [str(root_agent.id)]
        assert decoded["token_type"] == "access"

    async def test_mint_token_for_child_agent(
        self,
        token_service: TokenService,
        child_agent: Agent,
        active_rsa_key,
    ):
        """Test token minting for a child agent includes parent reference."""
        response = await token_service.mint_token(
            agent=child_agent,
            scopes=["limited.scope"],
        )

        decoded = jwt.decode(response.access_token, options={"verify_signature": False})

        assert decoded["sub"] == str(child_agent.id)
        assert decoded["parent_agent_id"] == str(child_agent.parent_agent_id)
        assert decoded["trust_level"] == TrustLevel.DELEGATED.value

    async def test_mint_refresh_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test minting a refresh token."""
        response = await token_service.mint_token(
            agent=root_agent,
            token_type="refresh",
        )

        assert response.access_token is not None
        assert response.refresh_token is None  # Refresh tokens don't include another refresh token

        # Refresh tokens have longer expiration
        expected_expires_in = settings.refresh_token_expire_days * 24 * 60 * 60
        assert abs(response.expires_in - expected_expires_in) < 2

        decoded = jwt.decode(response.access_token, options={"verify_signature": False})
        assert decoded["token_type"] == "refresh"

    async def test_mint_token_with_custom_expiration(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test minting token with custom expiration time."""
        custom_expires_minutes = 5

        response = await token_service.mint_token(
            agent=root_agent,
            expires_in_minutes=custom_expires_minutes,
        )

        assert response.expires_in == custom_expires_minutes * 60

    async def test_mint_token_with_ecdsa_algorithm(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_ecdsa_key,
    ):
        """Test minting token with ES256 algorithm."""
        response = await token_service.mint_token(
            agent=root_agent,
            algorithm=KeyAlgorithm.ES256,
        )

        # Verify token can be decoded and has correct algorithm
        header = jwt.get_unverified_header(response.access_token)
        assert header["alg"] == "ES256"
        assert header["kid"] == active_ecdsa_key.key_id

    async def test_mint_token_without_active_key_fails(
        self,
        token_service: TokenService,
        root_agent: Agent,
    ):
        """Test that minting fails when no active signing key exists."""
        with pytest.raises(TokenError) as exc_info:
            await token_service.mint_token(
                agent=root_agent,
                algorithm=KeyAlgorithm.RS256,
            )

        assert "No active signing key available" in str(exc_info.value)

    async def test_mint_token_includes_kid_header(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that minted token includes key ID in header."""
        response = await token_service.mint_token(agent=root_agent)

        header = jwt.get_unverified_header(response.access_token)
        assert header["kid"] == active_rsa_key.key_id
        assert header["alg"] == "RS256"
        assert header["typ"] == "JWT"

    async def test_mint_token_unique_jti(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that each token has a unique JTI."""
        response1 = await token_service.mint_token(agent=root_agent)
        response2 = await token_service.mint_token(agent=root_agent)

        decoded1 = jwt.decode(response1.access_token, options={"verify_signature": False})
        decoded2 = jwt.decode(response2.access_token, options={"verify_signature": False})

        assert decoded1["jti"] != decoded2["jti"]


class TestTokenValidation:
    """Tests for token validation functionality."""

    async def test_validate_valid_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test validation of a valid token."""
        audience = "https://api.example.com"
        scopes = ["read", "write"]

        # Mint a token
        response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
            audience=audience,
        )

        # Validate it
        result = await token_service.validate_token(
            token=response.access_token,
            expected_audience=audience,
        )

        assert result.valid is True
        assert result.error is None
        assert result.claims is not None
        assert result.claims.sub == str(root_agent.id)
        assert result.claims.scopes == scopes
        assert result.claims.agent_type == root_agent.agent_type
        assert result.claims.trust_level == root_agent.trust_level

    async def test_validate_token_verifies_signature(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that validation verifies token signature."""
        # Create a valid token
        response = await token_service.mint_token(agent=root_agent)
        token = response.access_token

        # Tamper with the token (change multiple characters in the signature to ensure invalidity)
        parts = token.split(".")
        # Replace first 10 chars of signature with different chars
        tampered_signature = "AAAAAAAAAA" + parts[2][10:]
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"

        # Validation should fail
        result = await token_service.validate_token(tampered_token)

        assert result.valid is False
        assert "signature" in result.error.lower() or "decode" in result.error.lower()

    async def test_validate_expired_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test validation of an expired token."""
        # Create a token that expires immediately
        response = await token_service.mint_token(
            agent=root_agent,
            expires_in_minutes=-1,  # Already expired
        )

        result = await token_service.validate_token(response.access_token)

        assert result.valid is False
        assert "expired" in result.error.lower()

    async def test_validate_token_wrong_audience(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test validation fails with wrong audience."""
        # Mint token for one audience
        response = await token_service.mint_token(
            agent=root_agent,
            audience="https://api1.example.com",
        )

        # Validate with different audience
        result = await token_service.validate_token(
            token=response.access_token,
            expected_audience="https://api2.example.com",
        )

        assert result.valid is False
        assert "audience" in result.error.lower()

    async def test_validate_token_missing_kid(
        self,
        token_service: TokenService,
    ):
        """Test validation fails when token has no key ID."""
        # Create a token without kid header (manually craft it)
        fake_token = jwt.encode(
            {"sub": "test", "exp": datetime.now(UTC).timestamp() + 300},
            "fake_key",
            algorithm="HS256",
        )

        result = await token_service.validate_token(fake_token)

        assert result.valid is False
        assert "key ID" in result.error or "key" in result.error.lower()

    async def test_validate_token_unknown_key_id(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test validation fails with unknown key ID."""
        # Create a token
        response = await token_service.mint_token(agent=root_agent)
        token = response.access_token

        # Decode and re-encode with different kid
        decoded = jwt.decode(token, options={"verify_signature": False})

        # Load the key to re-sign
        private_key = serialization.load_pem_private_key(
            active_rsa_key.private_key_pem.encode("utf-8"),
            password=None,
        )

        fake_token = jwt.encode(
            decoded,
            private_key,
            algorithm="RS256",
            headers={"kid": "unknown-key-id"},
        )

        result = await token_service.validate_token(fake_token)

        assert result.valid is False
        assert "Unknown signing key" in result.error

    async def test_validate_token_type(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test validation can check expected token type."""
        # Create an access token
        response = await token_service.mint_token(
            agent=root_agent,
            token_type="access",
        )

        # Validate expecting refresh token
        result = await token_service.validate_token(
            token=response.access_token,
            expected_token_type="refresh",
        )

        assert result.valid is False
        assert "token type" in result.error.lower()

    async def test_validate_token_with_delegation_chain(
        self,
        token_service: TokenService,
        root_agent: Agent,
        child_agent: Agent,
        active_rsa_key,
    ):
        """Test validation handles delegation chain correctly."""
        delegation_chain = [root_agent.id, child_agent.id]

        response = await token_service.mint_token(
            agent=child_agent,
            delegation_chain=delegation_chain,
        )

        result = await token_service.validate_token(response.access_token)

        assert result.valid is True
        assert result.claims is not None
        assert result.claims.delegation_chain == delegation_chain


class TestTokenIntrospection:
    """Tests for token introspection."""

    async def test_introspect_active_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test introspection of an active token."""
        scopes = ["read", "write"]
        response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
        )

        introspection = await token_service.introspect_token(response.access_token)

        assert introspection["active"] is True
        assert introspection["scope"] == "read write"
        assert introspection["client_id"] == str(root_agent.id)
        assert introspection["token_type"] == "access"
        assert introspection["agent_type"] == root_agent.agent_type.value
        assert introspection["trust_level"] == root_agent.trust_level.value
        assert "exp" in introspection
        assert "iat" in introspection
        assert "jti" in introspection

    async def test_introspect_invalid_token(
        self,
        token_service: TokenService,
    ):
        """Test introspection of an invalid token."""
        introspection = await token_service.introspect_token("invalid.token.here")

        assert introspection["active"] is False
        # Should not include other fields when active=false
        assert "scope" not in introspection
        assert "client_id" not in introspection

    async def test_introspect_expired_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test introspection of an expired token."""
        response = await token_service.mint_token(
            agent=root_agent,
            expires_in_minutes=-1,
        )

        introspection = await token_service.introspect_token(response.access_token)

        assert introspection["active"] is False


class TestTokenMetadataExtraction:
    """Tests for token metadata extraction."""

    async def test_extract_metadata_from_valid_token(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test extracting metadata from a valid token."""
        scopes = ["api.read", "api.write"]
        response = await token_service.mint_token(
            agent=root_agent,
            scopes=scopes,
        )

        metadata = await token_service.extract_metadata(response.access_token)

        assert metadata is not None
        assert metadata.key_id == active_rsa_key.key_id
        assert metadata.algorithm == "RS256"
        assert metadata.agent_id == root_agent.id
        assert metadata.agent_type == root_agent.agent_type
        assert metadata.trust_level == root_agent.trust_level
        assert metadata.scopes == scopes

    async def test_extract_metadata_from_invalid_token(
        self,
        token_service: TokenService,
    ):
        """Test extracting metadata from invalid token returns None."""
        metadata = await token_service.extract_metadata("not.a.token")

        assert metadata is None

    async def test_extract_metadata_does_not_verify_signature(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that metadata extraction works even with invalid signature."""
        # Create a valid token
        response = await token_service.mint_token(agent=root_agent)
        token = response.access_token

        # Tamper with signature but keep valid base64url format
        parts = token.split(".")
        # Use a valid base64url string but different content
        tampered_token = f"{parts[0]}.{parts[1]}.aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqqqrrrssstttuuuvvvwwwxxxyyyzzz"

        # Metadata extraction should still work (doesn't verify signature)
        metadata = await token_service.extract_metadata(tampered_token)

        assert metadata is not None
        assert metadata.agent_id == root_agent.id


class TestTokenJTIGeneration:
    """Tests for JWT ID generation."""

    async def test_jti_is_unique(self, token_service: TokenService):
        """Test that generated JTIs are unique."""
        jti1 = token_service._generate_jti()
        jti2 = token_service._generate_jti()
        jti3 = token_service._generate_jti()

        assert jti1 != jti2
        assert jti1 != jti3
        assert jti2 != jti3

    async def test_jti_is_url_safe(self, token_service: TokenService):
        """Test that JTI is URL-safe."""
        jti = token_service._generate_jti()

        # Should not contain characters that need URL encoding
        import string
        url_safe_chars = string.ascii_letters + string.digits + "-_"
        assert all(c in url_safe_chars for c in jti)


class TestTokenEdgeCases:
    """Tests for edge cases and error handling."""

    async def test_mint_token_with_multiple_audiences(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test minting token with multiple audiences."""
        audiences = ["https://api1.example.com", "https://api2.example.com"]

        response = await token_service.mint_token(
            agent=root_agent,
            audience=audiences,
        )

        decoded = jwt.decode(response.access_token, options={"verify_signature": False})
        assert decoded["aud"] == audiences

    async def test_mint_token_with_empty_scopes(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test minting token with empty scopes list."""
        response = await token_service.mint_token(
            agent=root_agent,
            scopes=[],
        )

        assert response.scope is None
        decoded = jwt.decode(response.access_token, options={"verify_signature": False})
        assert decoded["scopes"] == []

    async def test_mint_token_invalid_type_raises_error(
        self,
        token_service: TokenService,
        root_agent: Agent,
        active_rsa_key,
    ):
        """Test that invalid token type raises error."""
        with pytest.raises(TokenError) as exc_info:
            await token_service.mint_token(
                agent=root_agent,
                token_type="invalid_type",
            )

        assert "Unknown token type" in str(exc_info.value)
