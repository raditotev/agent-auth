"""Unit tests for ScopeService resolution logic (Task 3.1)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentauth.services.scope import ScopeService


class TestScopeResolution:
    """Tests for hierarchical scope resolution."""

    def test_wildcard_matches_sub_scopes(self) -> None:
        """'files.*' matches 'files.read' and 'files.write'."""
        assert ScopeService.scope_matches("files.*", "files.read") is True
        assert ScopeService.scope_matches("files.*", "files.write") is True
        assert ScopeService.scope_matches("files.*", "files.delete") is True

    def test_wildcard_does_not_match_other_prefix(self) -> None:
        """'files.*' does not match 'email.send'."""
        assert ScopeService.scope_matches("files.*", "email.send") is False

    def test_exact_scope_matches_itself(self) -> None:
        """'files.read' matches only 'files.read'."""
        assert ScopeService.scope_matches("files.read", "files.read") is True
        assert ScopeService.scope_matches("files.read", "files.write") is False

    def test_wildcard_does_not_match_parent(self) -> None:
        """'files.*' does not match 'files' (no dot after prefix)."""
        assert ScopeService.scope_matches("files.*", "files") is False

    @pytest.mark.asyncio
    async def test_resolve_wildcard_expands_to_matching_scopes(self) -> None:
        """resolve_scopes expands 'files.*' to all file sub-scopes."""
        mock_session = MagicMock()

        # Mock get_all_scopes to return a fixed set
        from agentauth.models.scope import Scope
        from uuid import uuid4
        from datetime import datetime, UTC

        def make_scope(name: str) -> Scope:
            s = Scope.__new__(Scope)
            s.name = name
            return s

        scopes_in_db = [make_scope(n) for n in [
            "files.read", "files.write", "files.delete", "email.send"
        ]]

        service = ScopeService(mock_session)
        with patch.object(service, "get_all_scopes", return_value=scopes_in_db):
            resolved = await service.resolve_scopes(["files.*"])

        assert "files.read" in resolved
        assert "files.write" in resolved
        assert "files.delete" in resolved
        assert "email.send" not in resolved

    @pytest.mark.asyncio
    async def test_resolve_explicit_scope_kept_as_is(self) -> None:
        """Explicit scope names are kept even if not in DB."""
        mock_session = MagicMock()
        service = ScopeService(mock_session)
        with patch.object(service, "get_all_scopes", return_value=[]):
            resolved = await service.resolve_scopes(["api.read"])

        assert "api.read" in resolved

    @pytest.mark.asyncio
    async def test_resolve_mixed_wildcard_and_explicit(self) -> None:
        """Mix of wildcards and explicit scopes resolved correctly."""
        from agentauth.models.scope import Scope

        def make_scope(name: str) -> Scope:
            s = Scope.__new__(Scope)
            s.name = name
            return s

        scopes_in_db = [make_scope(n) for n in [
            "files.read", "files.write", "email.send", "api.read"
        ]]

        mock_session = MagicMock()
        service = ScopeService(mock_session)
        with patch.object(service, "get_all_scopes", return_value=scopes_in_db):
            resolved = await service.resolve_scopes(["files.*", "email.send"])

        assert "files.read" in resolved
        assert "files.write" in resolved
        assert "email.send" in resolved
        assert "api.read" not in resolved
