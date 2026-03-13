"""Unit tests for configurable token lifetime per credential."""

import pytest
from pydantic import ValidationError

from agentauth.schemas.credential import CredentialCreate, CredentialResponse
from agentauth.models.credential import CredentialType


class TestCredentialCreateTokenLifetime:
    """Tests for token_lifetime_seconds validation in CredentialCreate."""

    def test_valid_token_lifetime_accepted(self):
        data = CredentialCreate(
            agent_id="00000000-0000-0000-0000-000000000001",
            token_lifetime_seconds=3600,
        )
        assert data.token_lifetime_seconds == 3600

    def test_minimum_valid_token_lifetime(self):
        data = CredentialCreate(
            agent_id="00000000-0000-0000-0000-000000000001",
            token_lifetime_seconds=60,
        )
        assert data.token_lifetime_seconds == 60

    def test_maximum_valid_token_lifetime(self):
        data = CredentialCreate(
            agent_id="00000000-0000-0000-0000-000000000001",
            token_lifetime_seconds=86400,
        )
        assert data.token_lifetime_seconds == 86400

    def test_token_lifetime_none_by_default(self):
        data = CredentialCreate(
            agent_id="00000000-0000-0000-0000-000000000001",
        )
        assert data.token_lifetime_seconds is None

    def test_token_lifetime_exceeds_max_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            CredentialCreate(
                agent_id="00000000-0000-0000-0000-000000000001",
                token_lifetime_seconds=100000,
            )
        errors = exc_info.value.errors()
        assert any("token_lifetime_seconds" in str(e) for e in errors)

    def test_token_lifetime_below_min_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            CredentialCreate(
                agent_id="00000000-0000-0000-0000-000000000001",
                token_lifetime_seconds=30,
            )
        errors = exc_info.value.errors()
        assert any("token_lifetime_seconds" in str(e) for e in errors)

    def test_token_lifetime_zero_raises_validation_error(self):
        with pytest.raises(ValidationError):
            CredentialCreate(
                agent_id="00000000-0000-0000-0000-000000000001",
                token_lifetime_seconds=0,
            )

    def test_token_lifetime_negative_raises_validation_error(self):
        with pytest.raises(ValidationError):
            CredentialCreate(
                agent_id="00000000-0000-0000-0000-000000000001",
                token_lifetime_seconds=-100,
            )


class TestCredentialResponseTokenLifetime:
    """Tests for token_lifetime_seconds in CredentialResponse."""

    def _make_mock_credential(self, token_lifetime_seconds=None):
        """Create a mock credential object."""
        from datetime import datetime, UTC
        from uuid import uuid4
        from unittest.mock import MagicMock

        cred = MagicMock()
        cred.id = uuid4()
        cred.agent_id = uuid4()
        cred.type = CredentialType.API_KEY
        cred.prefix = "abcd1234"
        cred.scopes = ["api.read"]
        cred.expires_at = None
        cred.last_used_at = None
        cred.last_rotated_at = None
        cred.revoked_at = None
        cred.credential_metadata = {}
        cred.token_lifetime_seconds = token_lifetime_seconds
        cred.created_at = datetime.now(UTC)
        cred.updated_at = datetime.now(UTC)
        cred.is_valid.return_value = True
        return cred

    def test_response_includes_token_lifetime_seconds(self):
        cred = self._make_mock_credential(token_lifetime_seconds=3600)
        response = CredentialResponse.from_model(cred)
        assert response.token_lifetime_seconds == 3600

    def test_response_token_lifetime_none_when_not_set(self):
        cred = self._make_mock_credential(token_lifetime_seconds=None)
        response = CredentialResponse.from_model(cred)
        assert response.token_lifetime_seconds is None

    def test_response_token_lifetime_included_in_serialization(self):
        cred = self._make_mock_credential(token_lifetime_seconds=1800)
        response = CredentialResponse.from_model(cred)
        data = response.model_dump()
        assert "token_lifetime_seconds" in data
        assert data["token_lifetime_seconds"] == 1800
