"""Unit tests for webhook delivery and HMAC signature verification."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from agentauth.tasks.webhooks import (
    SUPPORTED_EVENTS,
    _sign_payload,
    deliver_webhook,
    dispatch_event,
)


class TestSignPayload:
    """Tests for HMAC-SHA256 payload signing."""

    def test_sign_payload_returns_hex_string(self) -> None:
        """_sign_payload returns a valid hex string."""
        secret = "my-secret"
        payload = b'{"event_type": "credential.rotated"}'
        sig = _sign_payload(secret, payload)
        assert isinstance(sig, str)
        # Valid hex: each byte = 2 hex chars; SHA-256 = 32 bytes = 64 chars
        assert len(sig) == 64
        int(sig, 16)  # raises ValueError if not valid hex

    def test_sign_payload_matches_expected_hmac(self) -> None:
        """_sign_payload output matches manually computed HMAC-SHA256."""
        secret = "super-secret"
        payload = b"hello world"
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert _sign_payload(secret, payload) == expected

    def test_sign_payload_different_secrets_produce_different_sigs(self) -> None:
        """Different secrets produce different signatures for the same payload."""
        payload = b"same-payload"
        sig1 = _sign_payload("secret-a", payload)
        sig2 = _sign_payload("secret-b", payload)
        assert sig1 != sig2

    def test_sign_payload_different_payloads_produce_different_sigs(self) -> None:
        """Different payloads produce different signatures for the same secret."""
        secret = "shared-secret"
        sig1 = _sign_payload(secret, b"payload-one")
        sig2 = _sign_payload(secret, b"payload-two")
        assert sig1 != sig2

    def test_sign_payload_deterministic(self) -> None:
        """Same inputs always produce the same signature."""
        secret = "deterministic-secret"
        payload = b"deterministic-payload"
        assert _sign_payload(secret, payload) == _sign_payload(secret, payload)


class TestSupportedEvents:
    """Tests for SUPPORTED_EVENTS constant."""

    def test_supported_events_contains_expected_types(self) -> None:
        """SUPPORTED_EVENTS contains all documented event types."""
        assert "credential.rotated" in SUPPORTED_EVENTS
        assert "agent.suspended" in SUPPORTED_EVENTS
        assert "policy.violated" in SUPPORTED_EVENTS
        assert "delegation.revoked" in SUPPORTED_EVENTS


class TestDeliverWebhook:
    """Tests for the deliver_webhook coroutine."""

    def _make_subscription(
        self,
        *,
        subscription_id: str | None = None,
        enabled: bool = True,
        events: list[str] | None = None,
        url: str = "https://example.com/webhook",
        secret: str = "enc-secret",
    ) -> MagicMock:
        sub = MagicMock()
        sub.id = subscription_id or uuid4()
        sub.enabled = enabled
        sub.events = events or ["credential.rotated"]
        sub.url = url
        sub.secret = secret
        return sub

    @pytest.mark.asyncio
    async def test_deliver_skips_when_subscription_not_found(self) -> None:
        """deliver_webhook returns early if subscription does not exist."""
        sub_id = str(uuid4())

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings"),
        ):
            # Should not raise
            await deliver_webhook(sub_id, "credential.rotated", {"key": "value"})

        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_deliver_skips_when_subscription_disabled(self) -> None:
        """deliver_webhook returns early if subscription is disabled."""
        sub_id = str(uuid4())
        sub = self._make_subscription(enabled=False)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings"),
        ):
            await deliver_webhook(sub_id, "credential.rotated", {})

        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_deliver_skips_when_event_not_in_subscription(self) -> None:
        """deliver_webhook skips delivery if event_type not in subscription.events."""
        sub_id = str(uuid4())
        sub = self._make_subscription(events=["agent.suspended"])

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings"),
        ):
            await deliver_webhook(sub_id, "credential.rotated", {})

        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_deliver_success_on_first_attempt(self) -> None:
        """deliver_webhook records a successful delivery log on 2xx response."""
        sub_id = str(uuid4())
        sub = self._make_subscription()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_response = MagicMock()
        mock_http_response.status_code = 200

        mock_http_client = AsyncMock()
        mock_http_client.post = AsyncMock(return_value=mock_http_response)

        mock_settings = MagicMock()
        mock_settings.webhook_max_delivery_attempts = 3
        mock_settings.secret_key = "test-key"

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings", mock_settings),
            patch("agentauth.core.security.decrypt_secret", return_value="raw-secret"),
            patch("httpx.AsyncClient") as mock_http_class,
        ):
            mock_http_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_http_class.return_value.__aexit__ = AsyncMock(return_value=False)

            await deliver_webhook(sub_id, "credential.rotated", {"agent_id": "abc"})

        # One delivery log entry added
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        # Verify the log entry has success=True
        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.success is True
        assert log_entry.status_code == 200
        assert log_entry.attempt == 1

    @pytest.mark.asyncio
    async def test_deliver_retries_on_http_error_and_exhausts(self) -> None:
        """deliver_webhook retries up to max_attempts and records each failed attempt."""
        sub_id = str(uuid4())
        sub = self._make_subscription()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_response = MagicMock()
        mock_http_response.status_code = 500

        mock_http_client = AsyncMock()
        mock_http_client.post = AsyncMock(return_value=mock_http_response)

        mock_settings = MagicMock()
        mock_settings.webhook_max_delivery_attempts = 3
        mock_settings.secret_key = "test-key"

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings", mock_settings),
            patch("agentauth.core.security.decrypt_secret", return_value="raw-secret"),
            patch("agentauth.tasks.webhooks.asyncio.sleep", new_callable=AsyncMock),
            patch("httpx.AsyncClient") as mock_http_class,
        ):
            mock_http_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_http_class.return_value.__aexit__ = AsyncMock(return_value=False)

            await deliver_webhook(sub_id, "credential.rotated", {})

        # Should have attempted 3 times
        assert mock_session.add.call_count == 3
        # All attempts failed
        for call in mock_session.add.call_args_list:
            log = call[0][0]
            assert log.success is False
            assert log.status_code == 500

    @pytest.mark.asyncio
    async def test_deliver_records_error_message_on_exception(self) -> None:
        """deliver_webhook records error_message when HTTP request raises."""
        sub_id = str(uuid4())
        sub = self._make_subscription()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_client = AsyncMock()
        mock_http_client.post = AsyncMock(side_effect=ConnectionError("timeout"))

        mock_settings = MagicMock()
        mock_settings.webhook_max_delivery_attempts = 1
        mock_settings.secret_key = "test-key"

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings", mock_settings),
            patch("agentauth.core.security.decrypt_secret", return_value="raw-secret"),
            patch("httpx.AsyncClient") as mock_http_class,
        ):
            mock_http_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_http_class.return_value.__aexit__ = AsyncMock(return_value=False)

            await deliver_webhook(sub_id, "credential.rotated", {})

        log_entry = mock_session.add.call_args[0][0]
        assert log_entry.success is False
        assert log_entry.error_message == "timeout"
        assert log_entry.status_code is None

    @pytest.mark.asyncio
    async def test_deliver_signature_in_request_headers(self) -> None:
        """deliver_webhook includes X-AgentAuth-Signature header with sha256= prefix."""
        sub_id = str(uuid4())
        sub = self._make_subscription()

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sub
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_http_response = MagicMock()
        mock_http_response.status_code = 200

        captured_headers: dict = {}

        async def capture_post(url: str, *, content: bytes, headers: dict) -> MagicMock:
            captured_headers.update(headers)
            return mock_http_response

        mock_http_client = AsyncMock()
        mock_http_client.post = capture_post

        mock_settings = MagicMock()
        mock_settings.webhook_max_delivery_attempts = 1
        mock_settings.secret_key = "test-key"

        raw_secret = "my-raw-hmac-secret"

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.config.settings", mock_settings),
            patch("agentauth.core.security.decrypt_secret", return_value=raw_secret),
            patch("httpx.AsyncClient") as mock_http_class,
        ):
            mock_http_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_http_class.return_value.__aexit__ = AsyncMock(return_value=False)

            await deliver_webhook(sub_id, "credential.rotated", {"foo": "bar"})

        assert "X-AgentAuth-Signature" in captured_headers
        sig_header = captured_headers["X-AgentAuth-Signature"]
        assert sig_header.startswith("sha256=")
        # The hex after 'sha256=' must be 64 chars
        hex_part = sig_header[len("sha256="):]
        assert len(hex_part) == 64


class TestDispatchEvent:
    """Tests for the dispatch_event coroutine."""

    @pytest.mark.asyncio
    async def test_dispatch_ignores_unsupported_event(self) -> None:
        """dispatch_event does nothing for unsupported event types."""
        with patch("agentauth.core.database.get_session_maker") as mock_maker:
            await dispatch_event("unsupported.event", {"data": 1})
        mock_maker.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_calls_deliver_for_matching_subscriptions(self) -> None:
        """dispatch_event calls deliver_webhook once per matching subscription."""
        sub1 = MagicMock()
        sub1.id = uuid4()
        sub1.events = ["credential.rotated"]
        sub1.enabled = True

        sub2 = MagicMock()
        sub2.id = uuid4()
        sub2.events = ["agent.suspended"]  # Does not match
        sub2.enabled = True

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sub1, sub2]
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        delivered: list[str] = []

        async def fake_deliver(sub_id: str, event_type: str, payload: dict) -> None:
            delivered.append(sub_id)

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.tasks.webhooks.deliver_webhook", side_effect=fake_deliver),
        ):
            await dispatch_event("credential.rotated", {"test": True})

        assert delivered == [str(sub1.id)]

    @pytest.mark.asyncio
    async def test_dispatch_no_subscriptions_no_deliver(self) -> None:
        """dispatch_event does nothing when no enabled subscriptions exist."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_session_maker = MagicMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("agentauth.core.database.get_session_maker", return_value=mock_session_maker),
            patch("agentauth.tasks.webhooks.deliver_webhook") as mock_deliver,
        ):
            await dispatch_event("agent.suspended", {})

        mock_deliver.assert_not_called()
