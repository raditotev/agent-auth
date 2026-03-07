"""Unit tests for security utilities."""

import pytest

from agentauth.core.security import (
    generate_api_key,
    get_key_prefix,
    hash_secret,
    mask_secret,
    verify_secret,
)


class TestAPIKeyGeneration:
    """Tests for API key generation."""

    def test_generate_api_key_default_length(self) -> None:
        """Test generating API key with default length."""
        key = generate_api_key()
        assert len(key) == 32
        assert key.isalnum()

    def test_generate_api_key_custom_length(self) -> None:
        """Test generating API key with custom length."""
        key = generate_api_key(length=64)
        assert len(key) == 64
        assert key.isalnum()

    def test_generate_api_key_uniqueness(self) -> None:
        """Test that generated keys are unique."""
        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) == 100

    def test_generate_api_key_no_special_chars(self) -> None:
        """Test that generated keys contain only alphanumeric chars."""
        key = generate_api_key()
        # Base62: a-z, A-Z, 0-9
        assert all(c.isalnum() for c in key)
        assert "/" not in key
        assert "+" not in key
        assert "=" not in key


class TestSecretHashing:
    """Tests for secret hashing and verification."""

    def test_hash_secret(self) -> None:
        """Test hashing a secret."""
        secret = "my-secret-key-123"
        hash_value = hash_secret(secret)

        # Hash should be different from original
        assert hash_value != secret

        # Hash should start with $argon2id$
        assert hash_value.startswith("$argon2id$")

    def test_verify_secret_success(self) -> None:
        """Test verifying a correct secret."""
        secret = "my-secret-key-123"
        hash_value = hash_secret(secret)

        assert verify_secret(hash_value, secret) is True

    def test_verify_secret_failure(self) -> None:
        """Test verifying an incorrect secret."""
        secret = "my-secret-key-123"
        wrong_secret = "wrong-secret"
        hash_value = hash_secret(secret)

        assert verify_secret(hash_value, wrong_secret) is False

    def test_hash_uniqueness(self) -> None:
        """Test that same secret hashed twice produces different hashes (due to salt)."""
        secret = "my-secret-key-123"
        hash1 = hash_secret(secret)
        hash2 = hash_secret(secret)

        # Hashes should be different (different salts)
        assert hash1 != hash2

        # But both should verify correctly
        assert verify_secret(hash1, secret) is True
        assert verify_secret(hash2, secret) is True


class TestKeyPrefix:
    """Tests for key prefix extraction."""

    def test_get_key_prefix_default(self) -> None:
        """Test getting prefix with default length."""
        key = "abcd1234efgh5678ijkl"
        prefix = get_key_prefix(key)
        assert prefix == "abcd1234"
        assert len(prefix) == 8

    def test_get_key_prefix_custom_length(self) -> None:
        """Test getting prefix with custom length."""
        key = "abcd1234efgh5678ijkl"
        prefix = get_key_prefix(key, length=4)
        assert prefix == "abcd"
        assert len(prefix) == 4

    def test_get_key_prefix_longer_than_key(self) -> None:
        """Test getting prefix longer than key."""
        key = "short"
        prefix = get_key_prefix(key, length=10)
        assert prefix == "short"


class TestMaskSecret:
    """Tests for secret masking."""

    def test_mask_secret_default(self) -> None:
        """Test masking with default visible chars."""
        secret = "abcd1234efgh5678ijkl"
        masked = mask_secret(secret)
        assert masked == "abcd1234***"

    def test_mask_secret_custom_visible(self) -> None:
        """Test masking with custom visible chars."""
        secret = "abcd1234efgh5678ijkl"
        masked = mask_secret(secret, visible_chars=4)
        assert masked == "abcd***"

    def test_mask_secret_short_secret(self) -> None:
        """Test masking a secret shorter than visible chars."""
        secret = "short"
        masked = mask_secret(secret, visible_chars=8)
        assert masked == "***"

    def test_mask_secret_exact_length(self) -> None:
        """Test masking a secret of exact visible length."""
        secret = "12345678"
        masked = mask_secret(secret, visible_chars=8)
        assert masked == "***"
