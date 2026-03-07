"""Security utilities for hashing, encryption, and key generation."""

import base64
import hashlib
import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

# Argon2 hasher with secure defaults
# time_cost=3, memory_cost=65536, parallelism=4
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def generate_api_key(length: int = 32) -> str:
    """
    Generate a secure random API key.

    Uses base62 encoding (alphanumeric: a-z, A-Z, 0-9) for safe URL usage.

    Args:
        length: Length of the key in bytes (default 32)

    Returns:
        Base62-encoded random string
    """
    # Base62 alphabet (URL-safe)
    alphabet = string.ascii_letters + string.digits
    # Generate cryptographically secure random key
    return "".join(secrets.choice(alphabet) for _ in range(length))


def hash_secret(secret: str) -> str:
    """
    Hash a secret using Argon2.

    Args:
        secret: Plain text secret to hash

    Returns:
        Argon2 hash string
    """
    return ph.hash(secret)


def verify_secret(hash: str, secret: str) -> bool:
    """
    Verify a secret against its hash.

    Args:
        hash: Argon2 hash string
        secret: Plain text secret to verify

    Returns:
        True if secret matches hash, False otherwise
    """
    try:
        ph.verify(hash, secret)
        return True
    except VerifyMismatchError:
        return False


def _get_fernet(secret_key: str) -> Fernet:
    """Derive a Fernet instance from a secret key string."""
    key = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(secret: str, secret_key: str) -> str:
    """
    Symmetrically encrypt a secret using the application secret key.

    Use this for values that must be recovered server-side (e.g. webhook signing
    secrets used for HMAC payload signing). Do NOT use for password-like values —
    use hash_secret for those.

    Args:
        secret: Plain text secret to encrypt
        secret_key: Application secret key (from settings)

    Returns:
        Fernet-encrypted string (URL-safe base64)
    """
    return _get_fernet(secret_key).encrypt(secret.encode()).decode()


def decrypt_secret(encrypted: str, secret_key: str) -> str:
    """
    Decrypt a secret that was encrypted with encrypt_secret.

    Args:
        encrypted: Encrypted string produced by encrypt_secret
        secret_key: Application secret key (from settings)

    Returns:
        Original plain text secret
    """
    return _get_fernet(secret_key).decrypt(encrypted.encode()).decode()


def needs_rehash(hash: str) -> bool:
    """
    Check if a hash needs to be rehashed with current parameters.

    Args:
        hash: Argon2 hash string

    Returns:
        True if hash should be updated
    """
    return ph.check_needs_rehash(hash)


def get_key_prefix(key: str, length: int = 8) -> str:
    """
    Extract prefix from key for identification in logs.

    Args:
        key: Full API key
        length: Prefix length (default 8)

    Returns:
        Key prefix
    """
    return key[:length]


def mask_secret(secret: str, visible_chars: int = 8) -> str:
    """
    Mask a secret for display, showing only prefix.

    Args:
        secret: Secret to mask
        visible_chars: Number of characters to show (default 8)

    Returns:
        Masked secret (e.g., "abc12345***")
    """
    if len(secret) <= visible_chars:
        return "***"
    return secret[:visible_chars] + "***"
