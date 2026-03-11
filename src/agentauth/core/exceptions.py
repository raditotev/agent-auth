"""Custom exception hierarchy for AgentAuth."""

from typing import Any


class AgentAuthError(Exception):
    """Base exception for all AgentAuth errors."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        """Initialize exception."""
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class NotFoundError(AgentAuthError):
    """Resource not found."""

    pass


class AlreadyExistsError(AgentAuthError):
    """Resource already exists."""

    pass


class ValidationError(AgentAuthError):
    """Validation failed."""

    pass


class AuthenticationError(AgentAuthError):
    """Authentication failed."""

    pass


class AuthorizationError(AgentAuthError):
    """Authorization failed."""

    pass


class CredentialError(AgentAuthError):
    """Credential-related error."""

    pass


class TokenError(AgentAuthError):
    """Token-related error."""

    pass
