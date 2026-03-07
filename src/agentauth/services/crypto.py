"""Cryptographic service for key generation and JWK operations."""

import base64
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.signing_key import KeyAlgorithm, KeyStatus, SigningKey

logger = structlog.get_logger()


class CryptoService:
    """Service for cryptographic operations and key management."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize crypto service."""
        self.session = session

    async def generate_rsa_key_pair(
        self,
        key_size: int = 2048,
        activation_date: datetime | None = None,
        expiration_days: int = 90,
    ) -> SigningKey:
        """
        Generate an RSA key pair for RS256 signing.

        Args:
            key_size: RSA key size in bits (default 2048)
            activation_date: When key becomes active (default: now)
            expiration_days: Days until expiration (default: 90)

        Returns:
            SigningKey instance (not yet committed to DB)
        """
        logger.info("Generating RSA key pair", key_size=key_size)

        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        # Serialize private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),  # TODO: Encrypt in production
        ).decode("utf-8")

        # Extract public key
        public_key = private_key.public_key()

        # Serialize public key to PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Generate unique key ID
        key_id = self._generate_key_id()

        # Calculate dates
        activation = activation_date or datetime.now(UTC)
        expiration = activation + timedelta(days=expiration_days)

        # Create SigningKey instance
        signing_key = SigningKey(
            key_id=key_id,
            algorithm=KeyAlgorithm.RS256,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            status=KeyStatus.ACTIVE if activation <= datetime.now(UTC) else KeyStatus.PENDING,
            activation_date=activation,
            expiration_date=expiration,
        )

        logger.info(
            "RSA key pair generated",
            key_id=key_id,
            activation_date=activation.isoformat(),
            expiration_date=expiration.isoformat(),
        )

        return signing_key

    async def generate_ecdsa_key_pair(
        self,
        curve: ec.EllipticCurve = ec.SECP256R1(),
        activation_date: datetime | None = None,
        expiration_days: int = 90,
    ) -> SigningKey:
        """
        Generate an ECDSA key pair for ES256 signing.

        Args:
            curve: Elliptic curve to use (default: SECP256R1 / P-256)
            activation_date: When key becomes active (default: now)
            expiration_days: Days until expiration (default: 90)

        Returns:
            SigningKey instance (not yet committed to DB)
        """
        logger.info("Generating ECDSA key pair", curve=curve.name)

        # Generate ECDSA private key
        private_key = ec.generate_private_key(curve)

        # Serialize private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),  # TODO: Encrypt in production
        ).decode("utf-8")

        # Extract public key
        public_key = private_key.public_key()

        # Serialize public key to PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Generate unique key ID
        key_id = self._generate_key_id()

        # Calculate dates
        activation = activation_date or datetime.now(UTC)
        expiration = activation + timedelta(days=expiration_days)

        # Create SigningKey instance
        signing_key = SigningKey(
            key_id=key_id,
            algorithm=KeyAlgorithm.ES256,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            status=KeyStatus.ACTIVE if activation <= datetime.now(UTC) else KeyStatus.PENDING,
            activation_date=activation,
            expiration_date=expiration,
        )

        logger.info(
            "ECDSA key pair generated",
            key_id=key_id,
            activation_date=activation.isoformat(),
            expiration_date=expiration.isoformat(),
        )

        return signing_key

    async def get_active_signing_key(self, algorithm: KeyAlgorithm) -> SigningKey | None:
        """
        Get the currently active signing key for the given algorithm.

        Args:
            algorithm: Key algorithm to look for

        Returns:
            Active SigningKey or None
        """
        now = datetime.now(UTC)
        stmt = (
            select(SigningKey)
            .where(SigningKey.algorithm == algorithm)
            .where(SigningKey.status == KeyStatus.ACTIVE)
            .where(SigningKey.activation_date <= now)
            .where(SigningKey.expiration_date > now)
            .where(SigningKey.revoked_at.is_(None))
            .order_by(SigningKey.activation_date.desc())
            .limit(1)
        )

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_signing_key_by_id(self, key_id: str) -> SigningKey | None:
        """
        Get a signing key by its key_id.

        Args:
            key_id: The key identifier

        Returns:
            SigningKey or None
        """
        stmt = select(SigningKey).where(SigningKey.key_id == key_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all_valid_keys(self) -> list[SigningKey]:
        """
        Get all keys valid for verification (ACTIVE or EXPIRED, not REVOKED).

        Returns:
            List of SigningKey instances
        """
        stmt = (
            select(SigningKey)
            .where(SigningKey.status.in_([KeyStatus.ACTIVE, KeyStatus.EXPIRED]))
            .where(SigningKey.revoked_at.is_(None))
            .order_by(SigningKey.activation_date.desc())
        )

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def rotate_keys(self) -> dict[str, list[str]]:
        """
        Rotate keys: mark expired keys, generate new ones if needed.

        Key rotation logic:
        - Mark keys past expiration_date as EXPIRED
        - Check if there's an active key for each algorithm
        - Generate new key if no active key exists

        Returns:
            Dict with 'expired' and 'created' key IDs
        """
        logger.info("Starting key rotation")
        now = datetime.now(UTC)

        expired_key_ids: list[str] = []
        created_key_ids: list[str] = []

        # Mark expired keys
        stmt = (
            select(SigningKey)
            .where(SigningKey.status == KeyStatus.ACTIVE)
            .where(SigningKey.expiration_date <= now)
        )
        result = await self.session.execute(stmt)
        expired_keys = result.scalars().all()

        for key in expired_keys:
            key.mark_expired()
            expired_key_ids.append(key.key_id)
            logger.info("Key marked as expired", key_id=key.key_id, algorithm=key.algorithm.value)

        # Check for active keys for each algorithm
        for algorithm in KeyAlgorithm:
            active_key = await self.get_active_signing_key(algorithm)

            if active_key is None:
                logger.info("No active key found, generating new one", algorithm=algorithm.value)

                # Generate new key based on algorithm
                if algorithm == KeyAlgorithm.RS256:
                    new_key = await self.generate_rsa_key_pair(
                        activation_date=now,
                        expiration_days=90,  # 30 days active + 60 days for verification
                    )
                else:  # ES256
                    new_key = await self.generate_ecdsa_key_pair(
                        activation_date=now,
                        expiration_days=90,
                    )

                self.session.add(new_key)
                created_key_ids.append(new_key.key_id)
                logger.info(
                    "New key generated",
                    key_id=new_key.key_id,
                    algorithm=algorithm.value,
                )

        await self.session.commit()

        logger.info(
            "Key rotation completed",
            expired_count=len(expired_key_ids),
            created_count=len(created_key_ids),
        )

        return {
            "expired": expired_key_ids,
            "created": created_key_ids,
        }

    async def export_jwks(self) -> dict[str, Any]:
        """
        Export all valid public keys in JWKS (JSON Web Key Set) format.

        JWKS format follows RFC 7517.

        Returns:
            JWKS dict with 'keys' array
        """
        valid_keys = await self.get_all_valid_keys()

        jwks_keys = []
        for key in valid_keys:
            jwk = self._signing_key_to_jwk(key)
            jwks_keys.append(jwk)

        logger.info("JWKS exported", key_count=len(jwks_keys))

        return {"keys": jwks_keys}

    def _signing_key_to_jwk(self, key: SigningKey) -> dict[str, Any]:
        """
        Convert a SigningKey to JWK format.

        Args:
            key: SigningKey instance

        Returns:
            JWK dict
        """
        # Parse public key from PEM
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("utf-8"))

        # Base JWK fields
        jwk: dict[str, Any] = {
            "kid": key.key_id,
            "alg": key.algorithm.value,
            "use": "sig",  # Signature use
        }

        # Algorithm-specific fields
        if key.algorithm == KeyAlgorithm.RS256:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError(f"Expected RSA key for RS256, got {type(public_key)}")

            jwk["kty"] = "RSA"
            public_numbers = public_key.public_numbers()

            # Convert modulus and exponent to base64url
            jwk["n"] = self._int_to_base64url(public_numbers.n)
            jwk["e"] = self._int_to_base64url(public_numbers.e)

        elif key.algorithm == KeyAlgorithm.ES256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError(f"Expected EC key for ES256, got {type(public_key)}")

            jwk["kty"] = "EC"
            jwk["crv"] = "P-256"

            public_numbers = public_key.public_numbers()

            # Convert x and y coordinates to base64url
            jwk["x"] = self._int_to_base64url(public_numbers.x)
            jwk["y"] = self._int_to_base64url(public_numbers.y)

        return jwk

    @staticmethod
    def _int_to_base64url(value: int) -> str:
        """
        Convert an integer to base64url-encoded string.

        Args:
            value: Integer value

        Returns:
            Base64url-encoded string
        """
        # Convert to bytes (big-endian)
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder="big")

        # Base64url encode (no padding)
        encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
        return encoded.decode("utf-8")

    @staticmethod
    def _generate_key_id() -> str:
        """
        Generate a unique key identifier.

        Returns:
            Random key ID string
        """
        # Generate 16 random bytes and encode as hex
        return secrets.token_hex(16)
