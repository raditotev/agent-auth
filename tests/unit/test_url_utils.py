"""Unit tests for URL validation utilities (SSRF prevention)."""

import socket
from unittest.mock import patch

import pytest

from agentauth.core.exceptions import ValidationError
from agentauth.core.url_utils import validate_webhook_url


def _fake_getaddrinfo(ip: str):
    """Return a mock getaddrinfo result that resolves to the given IP."""

    def _resolver(hostname, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]

    return _resolver


class TestValidateWebhookUrl:
    """Tests for validate_webhook_url SSRF prevention."""

    def test_valid_public_https_url_accepted(self) -> None:
        """A public HTTPS URL resolving to a public IP is accepted."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("93.184.216.34"),
        ):
            validate_webhook_url("https://example.com/webhook")

    def test_valid_public_http_url_accepted(self) -> None:
        """A public HTTP URL resolving to a public IP is accepted."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("93.184.216.34"),
        ):
            validate_webhook_url("http://example.com/webhook")

    def test_loopback_127_rejected(self) -> None:
        """URL resolving to 127.0.0.1 is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("127.0.0.1"),
        ):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://127.0.0.1/hook")

    def test_localhost_hostname_rejected(self) -> None:
        """URL with 'localhost' hostname is rejected before DNS resolution."""
        with pytest.raises(ValidationError, match="localhost"):
            validate_webhook_url("http://localhost/hook")

    def test_private_10_network_rejected(self) -> None:
        """URL resolving to 10.x.x.x is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("10.0.0.1"),
        ):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://10.0.0.1/hook")

    def test_private_192_168_network_rejected(self) -> None:
        """URL resolving to 192.168.x.x is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("192.168.1.1"),
        ):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://192.168.1.1/hook")

    def test_private_172_16_network_rejected(self) -> None:
        """URL resolving to 172.16.x.x is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("172.16.0.1"),
        ):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://172.16.0.1/hook")

    def test_link_local_metadata_rejected(self) -> None:
        """AWS metadata endpoint (169.254.169.254) is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo("169.254.169.254"),
        ):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://169.254.169.254/latest/meta-data/")

    def test_ftp_scheme_rejected(self) -> None:
        """Non-HTTP schemes like ftp are rejected."""
        with pytest.raises(ValidationError, match="scheme"):
            validate_webhook_url("ftp://example.com/file")

    def test_no_scheme_rejected(self) -> None:
        """URL without a scheme is rejected."""
        with pytest.raises(ValidationError, match="scheme"):
            validate_webhook_url("example.com/webhook")

    def test_dns_resolution_failure_rejected(self) -> None:
        """URL with unresolvable hostname is rejected."""
        with patch(
            "agentauth.core.url_utils.socket.getaddrinfo",
            side_effect=socket.gaierror("Name resolution failed"),
        ):
            with pytest.raises(ValidationError, match="resolve"):
                validate_webhook_url("https://nonexistent.invalid/hook")

    def test_ipv6_loopback_rejected(self) -> None:
        """URL resolving to IPv6 loopback (::1) is rejected."""

        def _resolver(hostname, port, *args, **kwargs):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))]

        with patch("agentauth.core.url_utils.socket.getaddrinfo", side_effect=_resolver):
            with pytest.raises(ValidationError, match="private/internal"):
                validate_webhook_url("http://[::1]/hook")
