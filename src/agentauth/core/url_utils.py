"""URL utilities for safe logging."""

import re


def mask_url(url: str) -> str:
    """Mask credentials in a URL for safe logging.

    Replaces the userinfo portion (user:password@) with ***@.

    Args:
        url: URL string that may contain embedded credentials.

    Returns:
        URL with credentials masked.
    """
    return re.sub(r"://[^@/]*@", "://***@", url)
