"""Unit test conftest — overrides the session-scoped DB fixture so pure unit tests
can run without a live PostgreSQL instance."""

import pytest


@pytest.fixture(scope="session", autouse=True)
def ensure_test_database() -> None:  # type: ignore[override]
    """No-op override: unit tests do not require a real database."""
    return
