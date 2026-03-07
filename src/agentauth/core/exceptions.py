"""Custom exception hierarchy for AgentAuth."""

from typing import Any


class AgentAuthException(Exception):
    """Base exception for all AgentAuth errors."""

    def __init__(self, message: str, detail: dict[str, Any] | None = None) -> None:
        """Initialize exception."""
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class NotFoundError(AgentAuthException):
    """Resource not found."""

    pass


class AlreadyExistsError(AgentAuthException):
    """Resource already exists."""

    pass


class ValidationError(AgentAuthException):
    """Validation failed."""

    pass


class AuthenticationError(AgentAuthException):
    """Authentication failed."""

    pass


class AuthorizationError(AgentAuthException):
    """Authorization failed."""

    pass


class CredentialError(AgentAuthException):
    """Credential-related error."""

    pass


class TokenError(AgentAuthException):
    """Token-related error."""

    pass
