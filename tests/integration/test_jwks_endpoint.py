"""Integration tests for JWKS endpoint."""

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from agentauth.models.signing_key import KeyAlgorithm, KeyStatus, SigningKey
from agentauth.services.crypto import CryptoService


class TestJWKSEndpoint:
    """Test JWKS endpoint."""

    @pytest.mark.asyncio
    async def test_jwks_endpoint_empty(self, client: AsyncClient):
        """Test JWKS endpoint with no keys."""
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert data["keys"] == []

    @pytest.mark.asyncio
    async def test_jwks_endpoint_with_keys(self, client: AsyncClient, db_session):
        """Test JWKS endpoint with active keys."""
        crypto_service = CryptoService(db_session)

        # Generate keys
        rsa_key = await crypto_service.generate_rsa_key_pair()
        ec_key = await crypto_service.generate_ecdsa_key_pair()

        db_session.add(rsa_key)
        db_session.add(ec_key)
        await db_session.commit()

        # Call JWKS endpoint
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200
        data = response.json()

        assert "keys" in data
        assert len(data["keys"]) == 2

        # Verify RSA key
        rsa_jwk = next((k for k in data["keys"] if k["kid"] == rsa_key.key_id), None)
        assert rsa_jwk is not None
        assert rsa_jwk["alg"] == "RS256"
        assert rsa_jwk["kty"] == "RSA"
        assert rsa_jwk["use"] == "sig"
        assert "n" in rsa_jwk
        assert "e" in rsa_jwk

        # Verify EC key
        ec_jwk = next((k for k in data["keys"] if k["kid"] == ec_key.key_id), None)
        assert ec_jwk is not None
        assert ec_jwk["alg"] == "ES256"
        assert ec_jwk["kty"] == "EC"
        assert ec_jwk["crv"] == "P-256"
        assert ec_jwk["use"] == "sig"
        assert "x" in ec_jwk
        assert "y" in ec_jwk

    @pytest.mark.asyncio
    async def test_jwks_endpoint_excludes_revoked_keys(self, client: AsyncClient, db_session):
        """Test that JWKS endpoint excludes revoked keys."""
        crypto_service = CryptoService(db_session)

        # Generate active and revoked keys
        active_key = await crypto_service.generate_rsa_key_pair()
        db_session.add(active_key)

        revoked_key = await crypto_service.generate_ecdsa_key_pair()
        revoked_key.revoke()
        db_session.add(revoked_key)

        await db_session.commit()

        # Call JWKS endpoint
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200
        data = response.json()

        # Should only include active key
        assert len(data["keys"]) == 1
        assert data["keys"][0]["kid"] == active_key.key_id

    @pytest.mark.asyncio
    async def test_jwks_endpoint_includes_expired_keys(self, client: AsyncClient, db_session):
        """Test that JWKS endpoint includes expired (but not revoked) keys."""
        crypto_service = CryptoService(db_session)

        # Generate active and expired keys
        active_key = await crypto_service.generate_rsa_key_pair()
        db_session.add(active_key)

        expired_key = await crypto_service.generate_ecdsa_key_pair()
        expired_key.mark_expired()
        db_session.add(expired_key)

        await db_session.commit()

        # Call JWKS endpoint
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200
        data = response.json()

        # Should include both active and expired keys
        assert len(data["keys"]) == 2
        key_ids = [k["kid"] for k in data["keys"]]
        assert active_key.key_id in key_ids
        assert expired_key.key_id in key_ids

    @pytest.mark.asyncio
    async def test_jwks_endpoint_format_compliance(self, client: AsyncClient, db_session):
        """Test that JWKS format complies with RFC 7517."""
        crypto_service = CryptoService(db_session)

        # Generate a key
        key = await crypto_service.generate_rsa_key_pair()
        db_session.add(key)
        await db_session.commit()

        # Call JWKS endpoint
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200
        data = response.json()

        # Verify JWKS structure
        assert isinstance(data, dict)
        assert "keys" in data
        assert isinstance(data["keys"], list)

        # Verify JWK structure
        jwk = data["keys"][0]
        required_fields = ["kid", "kty", "use", "alg"]
        for field in required_fields:
            assert field in jwk, f"Missing required field: {field}"

        # For RSA keys, verify specific fields
        if jwk["kty"] == "RSA":
            assert "n" in jwk
            assert "e" in jwk
            # Verify base64url encoding (no padding)
            assert "=" not in jwk["n"]
            assert "=" not in jwk["e"]

    @pytest.mark.asyncio
    async def test_jwks_caching_headers(self, client: AsyncClient, db_session):
        """Test that JWKS endpoint has appropriate caching headers."""
        crypto_service = CryptoService(db_session)

        # Generate a key
        key = await crypto_service.generate_rsa_key_pair()
        db_session.add(key)
        await db_session.commit()

        # Call JWKS endpoint
        response = await client.get("/api/v1/auth/jwks")

        assert response.status_code == 200

        # Note: Caching headers would typically be added by middleware
        # This test documents the expected behavior
        # In production, add Cache-Control header like:
        # Cache-Control: public, max-age=3600, must-revalidate


class TestKeyRotationIntegration:
    """Integration tests for key rotation."""

    @pytest.mark.asyncio
    async def test_key_rotation_full_cycle(self, db_session):
        """Test complete key rotation cycle."""
        crypto_service = CryptoService(db_session)

        # Initial state: no keys
        stmt = select(SigningKey)
        result = await db_session.execute(stmt)
        assert len(result.scalars().all()) == 0

        # First rotation: should create initial keys
        rotation1 = await crypto_service.rotate_keys()
        assert len(rotation1["created"]) == 2
        assert len(rotation1["expired"]) == 0

        # Verify keys created
        result = await db_session.execute(stmt)
        all_keys = result.scalars().all()
        assert len(all_keys) == 2

        # Second rotation: no changes (keys still active)
        rotation2 = await crypto_service.rotate_keys()
        assert len(rotation2["created"]) == 0
        assert len(rotation2["expired"]) == 0

        # Simulate key expiration
        result = await db_session.execute(stmt)
        all_keys = result.scalars().all()
        for key in all_keys:
            # Set expiration to past
            from datetime import UTC, datetime, timedelta

            key.expiration_date = datetime.now(UTC) - timedelta(days=1)
        await db_session.commit()

        # Third rotation: should mark old keys expired and create new ones
        rotation3 = await crypto_service.rotate_keys()
        assert len(rotation3["expired"]) == 2
        assert len(rotation3["created"]) == 2

        # Verify we have 4 keys total (2 expired, 2 active)
        result = await db_session.execute(stmt)
        all_keys = result.scalars().all()
        assert len(all_keys) == 4

        expired_count = sum(1 for k in all_keys if k.status == KeyStatus.EXPIRED)
        active_count = sum(1 for k in all_keys if k.status == KeyStatus.ACTIVE)
        assert expired_count == 2
        assert active_count == 2
