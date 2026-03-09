"""Unit tests for application configuration and production validation."""

import pytest

from agentauth.config import Settings


class TestValidateProductionSettings:
    """Tests for Settings.validate_production_settings()."""

    def test_dev_environment_returns_warnings_does_not_raise(self) -> None:
        """In development, insecure defaults produce warnings but don't raise."""
        s = Settings(environment="development", secret_key="dev-secret-key-change-in-production")
        warnings = s.validate_production_settings()
        assert len(warnings) > 0
        # Must not raise

    def test_production_raises_on_default_secret_key(self) -> None:
        """Production with default SECRET_KEY must refuse to start."""
        s = Settings(
            environment="production",
            secret_key="dev-secret-key-change-in-production",
            signing_key_encryption_key="separate-strong-key",
        )
        with pytest.raises(ValueError, match="Refusing to start in production"):
            s.validate_production_settings()

    def test_staging_raises_on_default_secret_key(self) -> None:
        """Staging is treated the same as production for security checks."""
        s = Settings(
            environment="staging",
            secret_key="dev-secret-key-change-in-production",
            signing_key_encryption_key="separate-strong-key",
        )
        with pytest.raises(ValueError, match="Refusing to start in staging"):
            s.validate_production_settings()

    def test_production_raises_when_signing_key_encryption_key_missing(self) -> None:
        """Production must refuse when SIGNING_KEY_ENCRYPTION_KEY is not set."""
        s = Settings(
            environment="production",
            secret_key="a-strong-secret-key",
            signing_key_encryption_key="",
        )
        with pytest.raises(ValueError, match="Refusing to start in production"):
            s.validate_production_settings()

    def test_production_raises_when_signing_key_equals_secret_key(self) -> None:
        """Production must refuse when both keys share the same value."""
        s = Settings(
            environment="production",
            secret_key="shared-key",
            signing_key_encryption_key="shared-key",
        )
        with pytest.raises(ValueError, match="Refusing to start in production"):
            s.validate_production_settings()

    def test_production_passes_with_distinct_strong_keys(self) -> None:
        """Production with distinct, non-default keys should return no warnings."""
        s = Settings(
            environment="production",
            secret_key="a-strong-unique-secret-key",
            signing_key_encryption_key="a-different-strong-encryption-key",
        )
        warnings = s.validate_production_settings()
        assert warnings == []

    def test_warning_message_mentions_signing_key_when_missing(self) -> None:
        """Warning text should clearly describe the SIGNING_KEY_ENCRYPTION_KEY issue."""
        s = Settings(
            environment="development",
            secret_key="dev-secret-key-change-in-production",
            signing_key_encryption_key="",
        )
        warnings = s.validate_production_settings()
        joined = " ".join(warnings)
        assert "SIGNING_KEY_ENCRYPTION_KEY" in joined

    def test_warning_message_mentions_identical_keys(self) -> None:
        """Warning should tell the operator the two keys are identical."""
        s = Settings(
            environment="development",
            secret_key="same-key",
            signing_key_encryption_key="same-key",
        )
        warnings = s.validate_production_settings()
        joined = " ".join(warnings)
        assert "identical" in joined.lower() or "SIGNING_KEY_ENCRYPTION_KEY" in joined


class TestEffectiveSigningKeyEncryptionKey:
    """Tests for the effective_signing_key_encryption_key property."""

    def test_falls_back_to_secret_key_when_not_set(self) -> None:
        """When signing_key_encryption_key is empty, fall back to secret_key."""
        s = Settings(secret_key="my-secret", signing_key_encryption_key="")
        assert s.effective_signing_key_encryption_key == "my-secret"

    def test_returns_dedicated_key_when_set(self) -> None:
        """When signing_key_encryption_key is provided, use it exclusively."""
        s = Settings(secret_key="token-secret", signing_key_encryption_key="enc-key")
        assert s.effective_signing_key_encryption_key == "enc-key"

    def test_distinct_from_secret_key_when_both_set(self) -> None:
        """The two keys must be independent when both are configured."""
        s = Settings(secret_key="token-secret", signing_key_encryption_key="enc-key")
        assert s.effective_signing_key_encryption_key != s.secret_key
