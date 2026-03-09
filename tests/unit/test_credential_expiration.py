"""Unit tests for credential expiration and revocation rejection."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from agentauth.models.credential import CredentialType


def _make_credential(
    *,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> SimpleNamespace:
    """Build a lightweight credential-like object for is_valid() testing."""
    from agentauth.models.credential import Credential

    cred = SimpleNamespace()
    cred.id = uuid4()
    cred.agent_id = uuid4()
    cred.type = CredentialType.API_KEY
    cred.prefix = "abcd1234"
    cred.hash = "argon2hash"
    cred.scopes = ["read"]
    cred.expires_at = expires_at
    cred.revoked_at = revoked_at
    cred.last_used_at = None
    cred.last_rotated_at = None
    cred.credential_metadata = {}
    # Bind the actual is_valid method from Credential to this namespace
    cred.is_valid = lambda: Credential.is_valid(cred)  # type: ignore[arg-type]
    return cred


class TestCredentialIsValid:
    """Tests for Credential.is_valid()."""

    def test_valid_credential_with_no_expiry(self) -> None:
        """A credential with no expiry and no revocation is valid."""
        cred = _make_credential()
        assert cred.is_valid() is True

    def test_valid_credential_with_future_expiry(self) -> None:
        """A credential expiring in the future is valid."""
        cred = _make_credential(expires_at=datetime.now(UTC) + timedelta(days=30))
        assert cred.is_valid() is True

    def test_expired_credential_is_invalid(self) -> None:
        """A credential whose expires_at is in the past is invalid."""
        cred = _make_credential(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert cred.is_valid() is False

    def test_expired_by_one_microsecond_is_invalid(self) -> None:
        """Edge case: expiry at exactly one microsecond ago is invalid."""
        cred = _make_credential(
            expires_at=datetime.now(UTC) - timedelta(microseconds=1)
        )
        assert cred.is_valid() is False

    def test_revoked_credential_is_invalid(self) -> None:
        """A credential with revoked_at set is invalid regardless of expiry."""
        cred = _make_credential(revoked_at=datetime.now(UTC) - timedelta(hours=1))
        assert cred.is_valid() is False

    def test_revoked_and_not_expired_is_invalid(self) -> None:
        """Revocation takes precedence over a future expiry date."""
        cred = _make_credential(
            expires_at=datetime.now(UTC) + timedelta(days=365),
            revoked_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        assert cred.is_valid() is False

    def test_revoked_and_expired_is_invalid(self) -> None:
        """A credential that is both expired and revoked is invalid."""
        cred = _make_credential(
            expires_at=datetime.now(UTC) - timedelta(days=1),
            revoked_at=datetime.now(UTC) - timedelta(days=2),
        )
        assert cred.is_valid() is False

    def test_none_revoked_at_does_not_affect_validity(self) -> None:
        """revoked_at=None does not invalidate the credential."""
        cred = _make_credential(revoked_at=None, expires_at=None)
        assert cred.is_valid() is True

    def test_past_expiry_half_second_is_invalid(self) -> None:
        """500ms past expiry is definitely expired."""
        cred = _make_credential(expires_at=datetime.now(UTC) - timedelta(milliseconds=500))
        assert cred.is_valid() is False


class TestVerifyCredentialSkipsExpired:
    """
    verify_credential() silently skips invalid (expired/revoked) credentials
    and returns None — causing the caller (middleware) to reject the request.
    """

    @pytest.mark.asyncio
    async def test_expired_credential_returns_none(self) -> None:
        """verify_credential returns None when the only candidate is expired."""
        from agentauth.services.credential import CredentialService

        expired_cred = _make_credential(
            expires_at=datetime.now(UTC) - timedelta(hours=1)
        )

        mock_session = AsyncMock()
        service = CredentialService(mock_session)

        with patch.object(
            service,
            "get_credentials_by_prefix",
            new_callable=AsyncMock,
            return_value=[expired_cred],
        ):
            result = await service.verify_credential("abcd1234somethinglong")

        assert result is None

    @pytest.mark.asyncio
    async def test_revoked_credential_returns_none(self) -> None:
        """verify_credential returns None when the only candidate is revoked."""
        from agentauth.services.credential import CredentialService

        revoked_cred = _make_credential(
            revoked_at=datetime.now(UTC) - timedelta(minutes=10)
        )

        mock_session = AsyncMock()
        service = CredentialService(mock_session)

        with patch.object(
            service,
            "get_credentials_by_prefix",
            new_callable=AsyncMock,
            return_value=[revoked_cred],
        ):
            result = await service.verify_credential("abcd1234somethinglong")

        assert result is None

    @pytest.mark.asyncio
    async def test_valid_credential_returned_when_hash_matches(self) -> None:
        """verify_credential returns a valid credential when hash matches."""
        from agentauth.core.security import generate_api_key, hash_secret
        from agentauth.services.credential import CredentialService

        raw_key = generate_api_key()
        valid_cred = _make_credential(expires_at=datetime.now(UTC) + timedelta(days=30))
        valid_cred.hash = hash_secret(raw_key)
        valid_cred.prefix = raw_key[:8]

        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        service = CredentialService(mock_session)

        with patch.object(
            service,
            "get_credentials_by_prefix",
            new_callable=AsyncMock,
            return_value=[valid_cred],
        ):
            result = await service.verify_credential(raw_key)

        assert result is valid_cred

    @pytest.mark.asyncio
    async def test_expired_skipped_valid_sibling_returned(self) -> None:
        """
        When multiple credentials share a prefix, an expired one is skipped
        and the valid one is returned if the hash matches.
        """
        from agentauth.core.security import generate_api_key, hash_secret
        from agentauth.services.credential import CredentialService

        raw_key = generate_api_key()

        expired_cred = _make_credential(
            expires_at=datetime.now(UTC) - timedelta(hours=1)
        )
        expired_cred.prefix = raw_key[:8]
        expired_cred.hash = "wrong-hash"

        valid_cred = _make_credential(expires_at=datetime.now(UTC) + timedelta(days=1))
        valid_cred.prefix = raw_key[:8]
        valid_cred.hash = hash_secret(raw_key)

        mock_session = AsyncMock()
        mock_session.flush = AsyncMock()
        service = CredentialService(mock_session)

        with patch.object(
            service,
            "get_credentials_by_prefix",
            new_callable=AsyncMock,
            return_value=[expired_cred, valid_cred],
        ):
            result = await service.verify_credential(raw_key)

        assert result is valid_cred
