"""Scope service — registry and hierarchical resolution logic."""

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.models.scope import Scope

logger = structlog.get_logger()

# Default scopes seeded on startup
DEFAULT_SCOPES = [
    # Agent management
    ("agents.read", "Read agent information", "agents"),
    ("agents.write", "Create and update agents", "agents"),
    ("agents.delete", "Delete agents", "agents"),
    # Credentials
    ("credentials.read", "List and view credentials", "credentials"),
    ("credentials.write", "Create and rotate credentials", "credentials"),
    ("credentials.delete", "Revoke credentials", "credentials"),
    # Tokens
    ("tokens.issue", "Issue access tokens", "tokens"),
    ("tokens.introspect", "Introspect tokens", "tokens"),
    ("tokens.revoke", "Revoke tokens", "tokens"),
    # Policies
    ("policies.read", "Read policies", "policies"),
    ("policies.write", "Create and update policies", "policies"),
    ("policies.delete", "Delete policies", "policies"),
    # Delegations
    ("delegations.read", "View delegations", "delegations"),
    ("delegations.write", "Create delegations", "delegations"),
    ("delegations.delete", "Revoke delegations", "delegations"),
    # Files (example resource scopes)
    ("files.read", "Read files", "files"),
    ("files.write", "Write files", "files"),
    ("files.delete", "Delete files", "files"),
    # Email
    ("email.send", "Send emails", "email"),
    ("email.read", "Read emails", "email"),
    # Admin
    ("admin.full", "Full administrative access", "admin"),
    # General API access
    ("api.read", "General read access", "api"),
    ("api.write", "General write access", "api"),
]


class ScopeService:
    """Service for scope registry and resolution."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def seed_default_scopes(self) -> None:
        """Seed the database with default scopes if not already present."""
        for name, description, category in DEFAULT_SCOPES:
            existing = await self.session.execute(select(Scope).where(Scope.name == name))
            if existing.scalar_one_or_none() is None:
                scope = Scope(
                    name=name,
                    description=description,
                    category=category,
                    is_default=True,
                )
                self.session.add(scope)

        await self.session.commit()
        logger.info("Default scopes seeded")

    async def create_scope(
        self,
        name: str,
        description: str = "",
        category: str = "general",
    ) -> Scope:
        """Create a new scope."""
        scope = Scope(
            name=name,
            description=description,
            category=category,
            is_default=False,
        )
        self.session.add(scope)
        await self.session.commit()
        await self.session.refresh(scope)
        logger.info("Scope created", name=name)
        return scope

    async def get_all_scopes(self) -> list[Scope]:
        """Return all registered scopes."""
        result = await self.session.execute(select(Scope).order_by(Scope.name))
        return list(result.scalars().all())

    async def get_scope_by_name(self, name: str) -> Scope | None:
        """Look up a scope by exact name."""
        result = await self.session.execute(select(Scope).where(Scope.name == name))
        return result.scalar_one_or_none()

    async def resolve_scopes(self, requested: list[str]) -> list[str]:
        """
        Resolve wildcard scopes to concrete scope names.

        'files.*' expands to all scopes whose name starts with 'files.'.
        Explicit scopes that exist in the registry are kept as-is.
        Unknown non-wildcard scopes are passed through unchanged.
        """
        all_scopes = await self.get_all_scopes()
        all_scope_names = {s.name for s in all_scopes}

        resolved: set[str] = set()

        for scope in requested:
            if scope.endswith(".*"):
                # Wildcard: expand prefix
                prefix = scope[:-1]  # strip the '*', keep the dot
                matches = {name for name in all_scope_names if name.startswith(prefix)}
                resolved.update(matches)
            else:
                resolved.add(scope)

        return sorted(resolved)

    @staticmethod
    def scope_matches(scope_pattern: str, scope_name: str) -> bool:
        """
        Check if a scope pattern matches a concrete scope name.

        'files.*' matches 'files.read', 'files.write', etc.
        'files.read' matches only 'files.read'.
        """
        if scope_pattern.endswith(".*"):
            prefix = scope_pattern[:-1]  # strip '*'
            return scope_name.startswith(prefix)
        return scope_pattern == scope_name
