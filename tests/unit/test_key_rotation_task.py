"""Unit tests for key rotation task."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from agentauth.models.signing_key import KeyAlgorithm, KeyStatus, SigningKey
from agentauth.services.crypto import CryptoService


class TestKeyRotationSchedule:
    """Test key rotation scheduling configuration."""

    def test_celery_beat_schedule_configured(self):
        """Test that Celery beat schedule is configured."""
        from agentauth.tasks.key_rotation import celery_app

        beat_schedule = celery_app.conf.beat_schedule

        assert "rotate-signing-keys-daily" in beat_schedule

        task_config = beat_schedule["rotate-signing-keys-daily"]
        assert task_config["task"] == "agentauth.rotate_signing_keys"
        assert task_config["schedule"] == 86400.0  # 24 hours

    def test_celery_app_configuration(self):
        """Test Celery app is configured correctly."""
        from agentauth.tasks.key_rotation import celery_app

        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.result_serializer == "json"
        assert celery_app.conf.timezone == "UTC"
        assert celery_app.conf.enable_utc is True


class TestKeyRotationLogic:
    """Test key rotation business logic."""

    @pytest.mark.asyncio
    async def test_rotation_strategy_30_day_active_60_day_verification(self, db_session):
        """Test that rotation follows the 30+60 day strategy."""
        crypto_service = CryptoService(db_session)

        # Generate key with specific dates
        activation = datetime.now(UTC)
        key = await crypto_service.generate_rsa_key_pair(
            activation_date=activation,
            expiration_days=90,
        )

        # Verify expiration is 90 days from activation
        expected_expiration = activation + timedelta(days=90)
        assert abs((key.expiration_date - expected_expiration).total_seconds()) < 1

        # Key should be active for signing until expiration
        assert key.is_active()

        # After expiration, key should still be valid for verification
        key.mark_expired()
        assert not key.is_active()
        assert key.is_valid_for_verification()
        assert key.should_be_in_jwks()

    @pytest.mark.asyncio
    async def test_multiple_algorithm_support(self, db_session):
        """Test that rotation handles multiple algorithms."""
        crypto_service = CryptoService(db_session)

        # Run rotation - should create keys for all algorithms
        result = await crypto_service.rotate_keys()

        # Verify keys for both algorithms
        stmt_rsa = select(SigningKey).where(SigningKey.algorithm == KeyAlgorithm.RS256)
        stmt_es = select(SigningKey).where(SigningKey.algorithm == KeyAlgorithm.ES256)

        result_rsa = await db_session.execute(stmt_rsa)
        result_es = await db_session.execute(stmt_es)

        rsa_keys = result_rsa.scalars().all()
        es_keys = result_es.scalars().all()

        assert len(rsa_keys) > 0
        assert len(es_keys) > 0

    @pytest.mark.asyncio
    async def test_old_keys_kept_for_verification(self, db_session):
        """Test that expired keys are kept for token verification."""
        crypto_service = CryptoService(db_session)

        # Create and expire a key
        old_key = await crypto_service.generate_rsa_key_pair()
        old_key.expiration_date = datetime.now(UTC) - timedelta(days=1)
        db_session.add(old_key)
        await db_session.commit()

        # Rotate - should mark old key as expired and create new one
        await crypto_service.rotate_keys()

        # Verify old key still exists and can be used for verification
        await db_session.refresh(old_key)
        assert old_key.status == KeyStatus.EXPIRED
        assert old_key.is_valid_for_verification()
        assert old_key.should_be_in_jwks()

        # Verify it's still in the database
        stmt = select(SigningKey).where(SigningKey.id == old_key.id)
        result = await db_session.execute(stmt)
        assert result.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_rotation_creates_keys_for_all_algorithms(self, db_session):
        """Test that initial rotation creates keys for all algorithms."""
        crypto_service = CryptoService(db_session)

        # Initial state: no keys
        stmt = select(SigningKey)
        result = await db_session.execute(stmt)
        assert len(result.scalars().all()) == 0

        # Run rotation
        rotation_result = await crypto_service.rotate_keys()

        # Should create keys for both algorithms
        assert len(rotation_result["created"]) == 2
        assert len(rotation_result["expired"]) == 0

        # Verify both algorithm types were created
        stmt = select(SigningKey).where(SigningKey.status == KeyStatus.ACTIVE)
        result = await db_session.execute(stmt)
        active_keys = result.scalars().all()

        algorithms = {k.algorithm for k in active_keys}
        assert KeyAlgorithm.RS256 in algorithms
        assert KeyAlgorithm.ES256 in algorithms
