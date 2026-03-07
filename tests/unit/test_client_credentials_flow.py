"""Unit tests for client_credentials grant flow logic."""

import pytest

from agentauth.api.v1.auth import _parse_scopes, _validate_scopes


class TestScopeValidation:
    """Test scope validation logic."""

    def test_parse_scopes_empty_string(self) -> None:
        """Test parsing empty scope string."""
        result = _parse_scopes("")
        assert result == []

    def test_parse_scopes_none(self) -> None:
        """Test parsing None scope."""
        result = _parse_scopes(None)
        assert result == []

    def test_parse_scopes_single_scope(self) -> None:
        """Test parsing single scope."""
        result = _parse_scopes("files.read")
        assert result == ["files.read"]

    def test_parse_scopes_multiple_scopes(self) -> None:
        """Test parsing multiple scopes."""
        result = _parse_scopes("files.read files.write email.send")
        assert result == ["files.read", "files.write", "email.send"]

    def test_parse_scopes_extra_whitespace(self) -> None:
        """Test parsing with extra whitespace."""
        result = _parse_scopes("  files.read   files.write  ")
        assert result == ["files.read", "files.write"]

    def test_validate_scopes_no_request_grants_all(self) -> None:
        """Test that no requested scopes grants all allowed scopes."""
        allowed = ["files.read", "files.write", "email.send"]
        result = _validate_scopes([], allowed)
        assert result == allowed

    def test_validate_scopes_subset_allowed(self) -> None:
        """Test that requesting subset of allowed scopes is permitted."""
        requested = ["files.read", "files.write"]
        allowed = ["files.read", "files.write", "email.send", "admin.access"]
        result = _validate_scopes(requested, allowed)
        assert result == requested

    def test_validate_scopes_exact_match_allowed(self) -> None:
        """Test that requesting exactly allowed scopes is permitted."""
        requested = ["files.read", "files.write"]
        allowed = ["files.read", "files.write"]
        result = _validate_scopes(requested, allowed)
        assert result == requested

    def test_validate_scopes_escalation_denied(self) -> None:
        """Test that scope escalation is denied."""
        requested = ["files.read", "files.write", "admin.access"]
        allowed = ["files.read", "files.write"]
        result = _validate_scopes(requested, allowed)
        assert result is None

    def test_validate_scopes_single_extra_scope_denied(self) -> None:
        """Test that requesting even one extra scope is denied."""
        requested = ["files.read", "admin.delete"]
        allowed = ["files.read"]
        result = _validate_scopes(requested, allowed)
        assert result is None

    def test_validate_scopes_completely_different_denied(self) -> None:
        """Test that requesting completely different scopes is denied."""
        requested = ["admin.access"]
        allowed = ["files.read", "files.write"]
        result = _validate_scopes(requested, allowed)
        assert result is None

    def test_validate_scopes_order_independence(self) -> None:
        """Test that scope order doesn't matter."""
        requested = ["email.send", "files.read", "files.write"]
        allowed = ["files.write", "email.send", "files.read", "admin.access"]
        result = _validate_scopes(requested, allowed)
        assert set(result) == set(requested)

    def test_validate_scopes_empty_allowed_list(self) -> None:
        """Test validation with empty allowed scopes."""
        requested = ["files.read"]
        allowed = []
        result = _validate_scopes(requested, allowed)
        assert result is None

    def test_validate_scopes_empty_both_lists(self) -> None:
        """Test validation with both lists empty."""
        result = _validate_scopes([], [])
        assert result == []

    def test_validate_scopes_duplicate_scopes_in_request(self) -> None:
        """Test that duplicate scopes in request are handled."""
        requested = ["files.read", "files.read", "files.write"]
        allowed = ["files.read", "files.write", "email.send"]
        result = _validate_scopes(requested, allowed)
        # Should still validate (set comparison removes duplicates)
        assert result == requested
