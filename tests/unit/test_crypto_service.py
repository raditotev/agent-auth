"""Unit tests for crypto service."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select

from agentauth.models.signing_key import KeyAlgorithm, KeyStatus, SigningKey
from agentauth.services.crypto import CryptoService


class TestCryptoService:
    """Test CryptoService."""

    @pytest.mark.asyncio
    async def test_generate_rsa_key_pair(self, db_session):
        """Test RSA key pair generation."""
        crypto_service = CryptoService(db_session)

        # Generate key pair
        key = await crypto_service.generate_rsa_key_pair(key_size=2048)

        assert key is not None
        assert key.algorithm == KeyAlgorithm.RS256
        assert key.status == KeyStatus.ACTIVE
        assert key.key_id is not None
        assert len(key.key_id) == 32  # 16 bytes = 32 hex chars

        # Verify private key
        assert key.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
        private_key = serialization.load_pem_private_key(
            key.private_key_pem.encode("utf-8"),
            password=None,
        )
        assert isinstance(private_key, rsa.RSAPrivateKey)

        # Verify public key
        assert key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("utf-8"))
        assert isinstance(public_key, rsa.RSAPublicKey)

        # Verify dates
        assert key.activation_date is not None
        assert key.expiration_date is not None
        assert key.expiration_date > key.activation_date

    @pytest.mark.asyncio
    async def test_generate_ecdsa_key_pair(self, db_session):
        """Test ECDSA key pair generation."""
        crypto_service = CryptoService(db_session)

        # Generate key pair
        key = await crypto_service.generate_ecdsa_key_pair()

        assert key is not None
        assert key.algorithm == KeyAlgorithm.ES256
        assert key.status == KeyStatus.ACTIVE
        assert key.key_id is not None

        # Verify private key
        assert key.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
        private_key = serialization.load_pem_private_key(
            key.private_key_pem.encode("utf-8"),
            password=None,
        )
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

        # Verify public key
        assert key.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("utf-8"))
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

    @pytest.mark.asyncio
    async def test_generate_key_with_future_activation(self, db_session):
        """Test generating key with future activation date."""
        crypto_service = CryptoService(db_session)

        # Generate key that activates in 7 days
        activation = datetime.now(UTC) + timedelta(days=7)
        key = await crypto_service.generate_rsa_key_pair(activation_date=activation)

        assert key.status == KeyStatus.PENDING
        assert key.activation_date == activation
        assert not key.is_active()

    @pytest.mark.asyncio
    async def test_get_active_signing_key(self, db_session):
        """Test retrieving active signing key."""
        crypto_service = CryptoService(db_session)

        # Generate and save an RSA key
        rsa_key = await crypto_service.generate_rsa_key_pair()
        db_session.add(rsa_key)
        await db_session.commit()

        # Retrieve active key
        active_key = await crypto_service.get_active_signing_key(KeyAlgorithm.RS256)

        assert active_key is not None
        assert active_key.key_id == rsa_key.key_id
        assert active_key.algorithm == KeyAlgorithm.RS256
        assert active_key.is_active()

    @pytest.mark.asyncio
    async def test_get_active_signing_key_none_if_expired(self, db_session):
        """Test that expired keys are not returned as active."""
        crypto_service = CryptoService(db_session)

        # Generate expired key
        activation = datetime.now(UTC) - timedelta(days=100)
        expiration = datetime.now(UTC) - timedelta(days=10)
        key = await crypto_service.generate_rsa_key_pair(
            activation_date=activation,
            expiration_days=0,
        )
        key.expiration_date = expiration
        key.status = KeyStatus.EXPIRED

        db_session.add(key)
        await db_session.commit()

        # Should not find active key
        active_key = await crypto_service.get_active_signing_key(KeyAlgorithm.RS256)
        assert active_key is None

    @pytest.mark.asyncio
    async def test_get_signing_key_by_id(self, db_session):
        """Test retrieving key by key_id."""
        crypto_service = CryptoService(db_session)

        # Generate and save key
        key = await crypto_service.generate_rsa_key_pair()
        db_session.add(key)
        await db_session.commit()

        # Retrieve by key_id
        retrieved_key = await crypto_service.get_signing_key_by_id(key.key_id)

        assert retrieved_key is not None
        assert retrieved_key.id == key.id
        assert retrieved_key.key_id == key.key_id

    @pytest.mark.asyncio
    async def test_get_all_valid_keys(self, db_session):
        """Test retrieving all valid keys."""
        crypto_service = CryptoService(db_session)

        # Generate multiple keys
        active_rsa = await crypto_service.generate_rsa_key_pair()
        active_rsa.status = KeyStatus.ACTIVE
        db_session.add(active_rsa)

        expired_rsa = await crypto_service.generate_rsa_key_pair()
        expired_rsa.status = KeyStatus.EXPIRED
        db_session.add(expired_rsa)

        revoked_rsa = await crypto_service.generate_rsa_key_pair()
        revoked_rsa.revoke()
        db_session.add(revoked_rsa)

        active_ec = await crypto_service.generate_ecdsa_key_pair()
        active_ec.status = KeyStatus.ACTIVE
        db_session.add(active_ec)

        await db_session.commit()

        # Get all valid keys
        valid_keys = await crypto_service.get_all_valid_keys()

        # Should get ACTIVE and EXPIRED, but not REVOKED
        assert len(valid_keys) == 3
        key_ids = [k.key_id for k in valid_keys]
        assert active_rsa.key_id in key_ids
        assert expired_rsa.key_id in key_ids
        assert revoked_rsa.key_id not in key_ids
        assert active_ec.key_id in key_ids

    @pytest.mark.asyncio
    async def test_export_jwks_rsa(self, db_session):
        """Test exporting RSA key to JWKS format."""
        crypto_service = CryptoService(db_session)

        # Generate and save RSA key
        key = await crypto_service.generate_rsa_key_pair()
        db_session.add(key)
        await db_session.commit()

        # Export JWKS
        jwks = await crypto_service.export_jwks()

        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

        jwk = jwks["keys"][0]
        assert jwk["kid"] == key.key_id
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert jwk["kty"] == "RSA"
        assert "n" in jwk  # modulus
        assert "e" in jwk  # exponent

    @pytest.mark.asyncio
    async def test_export_jwks_ecdsa(self, db_session):
        """Test exporting ECDSA key to JWKS format."""
        crypto_service = CryptoService(db_session)

        # Generate and save ECDSA key
        key = await crypto_service.generate_ecdsa_key_pair()
        db_session.add(key)
        await db_session.commit()

        # Export JWKS
        jwks = await crypto_service.export_jwks()

        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

        jwk = jwks["keys"][0]
        assert jwk["kid"] == key.key_id
        assert jwk["alg"] == "ES256"
        assert jwk["use"] == "sig"
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "x" in jwk  # x coordinate
        assert "y" in jwk  # y coordinate

    @pytest.mark.asyncio
    async def test_export_jwks_multiple_keys(self, db_session):
        """Test exporting multiple keys to JWKS."""
        crypto_service = CryptoService(db_session)

        # Generate multiple valid keys
        rsa_key = await crypto_service.generate_rsa_key_pair()
        db_session.add(rsa_key)

        ec_key = await crypto_service.generate_ecdsa_key_pair()
        db_session.add(ec_key)

        # Add a revoked key (should not appear in JWKS)
        revoked_key = await crypto_service.generate_rsa_key_pair()
        revoked_key.revoke()
        db_session.add(revoked_key)

        await db_session.commit()

        # Export JWKS
        jwks = await crypto_service.export_jwks()

        # Should only have 2 keys (RSA and EC, not revoked)
        assert len(jwks["keys"]) == 2
        key_ids = [k["kid"] for k in jwks["keys"]]
        assert rsa_key.key_id in key_ids
        assert ec_key.key_id in key_ids
        assert revoked_key.key_id not in key_ids

    @pytest.mark.asyncio
    async def test_rotate_keys_marks_expired(self, db_session):
        """Test that key rotation marks expired keys."""
        crypto_service = CryptoService(db_session)

        # Create an expired key
        past_activation = datetime.now(UTC) - timedelta(days=100)
        past_expiration = datetime.now(UTC) - timedelta(days=1)

        expired_key = await crypto_service.generate_rsa_key_pair(
            activation_date=past_activation,
            expiration_days=0,
        )
        expired_key.expiration_date = past_expiration
        expired_key.status = KeyStatus.ACTIVE  # Still marked as ACTIVE (needs rotation)
        db_session.add(expired_key)
        await db_session.commit()

        # Rotate keys
        result = await crypto_service.rotate_keys()

        # Check that key was marked expired
        assert len(result["expired"]) == 1
        assert expired_key.key_id in result["expired"]

        # Verify in database
        await db_session.refresh(expired_key)
        assert expired_key.status == KeyStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_rotate_keys_generates_new_if_none_active(self, db_session):
        """Test that key rotation generates new keys when none active."""
        crypto_service = CryptoService(db_session)

        # Rotate keys (no keys exist)
        result = await crypto_service.rotate_keys()

        # Should generate new keys for both algorithms
        assert len(result["created"]) == 2

        # Verify keys in database
        stmt = select(SigningKey).where(SigningKey.status == KeyStatus.ACTIVE)
        result_db = await db_session.execute(stmt)
        active_keys = result_db.scalars().all()

        assert len(active_keys) == 2
        algorithms = {k.algorithm for k in active_keys}
        assert KeyAlgorithm.RS256 in algorithms
        assert KeyAlgorithm.ES256 in algorithms

    @pytest.mark.asyncio
    async def test_rotate_keys_does_not_generate_if_active_exists(self, db_session):
        """Test that rotation doesn't generate new key if active one exists."""
        crypto_service = CryptoService(db_session)

        # Create active RSA key
        active_key = await crypto_service.generate_rsa_key_pair()
        db_session.add(active_key)
        await db_session.commit()

        # Get count before rotation
        stmt = select(SigningKey).where(SigningKey.algorithm == KeyAlgorithm.RS256)
        result = await db_session.execute(stmt)
        keys_before = len(result.scalars().all())

        # Rotate keys
        rotation_result = await crypto_service.rotate_keys()

        # Should NOT create a new RSA key (active one exists)
        # Should create an ES256 key (none exists)
        # Check if any created keys are RSA
        rsa_created = False
        for kid in rotation_result["created"]:
            key = await crypto_service.get_signing_key_by_id(kid)
            if key and key.algorithm == KeyAlgorithm.RS256:
                rsa_created = True
                break

        assert not rsa_created, "Should not create new RSA key when active one exists"

        # Verify RSA key count unchanged
        result = await db_session.execute(stmt)
        keys_after = len(result.scalars().all())
        assert keys_after == keys_before

    @pytest.mark.asyncio
    async def test_key_lifecycle_methods(self, db_session):
        """Test SigningKey lifecycle methods."""
        crypto_service = CryptoService(db_session)

        # Create active key
        key = await crypto_service.generate_rsa_key_pair()

        # Test is_active
        assert key.is_active()
        assert key.is_valid_for_verification()
        assert key.should_be_in_jwks()

        # Mark as expired
        key.mark_expired()
        assert not key.is_active()
        assert key.is_valid_for_verification()
        assert key.should_be_in_jwks()
        assert key.status == KeyStatus.EXPIRED

        # Revoke key
        key.revoke()
        assert not key.is_active()
        assert not key.is_valid_for_verification()
        assert not key.should_be_in_jwks()
        assert key.status == KeyStatus.REVOKED
        assert key.revoked_at is not None
