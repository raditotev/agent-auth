"""URL utilities for safe logging and SSRF prevention."""

import ipaddress
import re
import socket
from urllib.parse import urlparse

from agentauth.core.exceptions import ValidationError

# IP networks considered internal/private and forbidden for webhooks.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain"}


def validate_webhook_url(url: str) -> None:
    """Validate that a webhook URL does not target internal networks (SSRF prevention).

    Raises:
        ValidationError: If the URL scheme is invalid, hostname resolves to a
            private/internal IP, or the hostname is a known local alias.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"Webhook URL scheme must be http or https, got '{parsed.scheme}'",
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("Webhook URL must include a hostname")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValidationError(
            f"Webhook URL must not target localhost (got '{hostname}')",
        )

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValidationError(f"Could not resolve webhook hostname '{hostname}'") from exc

    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValidationError(
                    f"Webhook URL must not target private/internal network "
                    f"('{hostname}' resolves to {ip})",
                )


def mask_url(url: str) -> str:
    """Mask credentials in a URL for safe logging.

    Replaces the userinfo portion (user:password@) with ***@.

    Args:
        url: URL string that may contain embedded credentials.

    Returns:
        URL with credentials masked.
    """
    return re.sub(r"://[^@/]*@", "://***@", url)
