"""Delegation service — lifecycle and chain traversal."""

import json
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.core.exceptions import AuthenticationError
from agentauth.models.delegation import Delegation

logger = structlog.get_logger()

# Redis key prefix and TTL for cached delegation chains
_CHAIN_CACHE_PREFIX = "delegation:chain:"
_CHAIN_CACHE_TTL = 60  # seconds — intentionally short; chains change on revoke/create


def _scope_covered_by(requested: str, allowed: str) -> bool:
    """Return True if `allowed` covers `requested` (supports wildcard suffix `.*`)."""
    if allowed.endswith(".*"):
        prefix = allowed[:-1]  # strip '*', keep the trailing dot
        return requested.startswith(prefix)
    return requested == allowed


def _scope_is_delegatable(scope: str, effective_scopes: set[str]) -> bool:
    """Return True if `scope` is covered by at least one entry in `effective_scopes`."""
    return any(_scope_covered_by(scope, eff) for eff in effective_scopes)


class DelegationService:
    """Service for creating, validating, and revoking delegations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_delegation(
        self,
        delegator_agent_id: UUID,
        delegate_agent_id: UUID,
        scopes: list[str],
        constraints: dict | None = None,
        max_chain_depth: int = 3,
        expires_at: datetime | None = None,
    ) -> Delegation:
        """
        Create a delegation from delegator to delegate.

        Validates:
        - Scopes are a subset of delegator's effective scopes
        - Chain depth does not exceed the maximum
        - Both agents are active
        """
        from agentauth.models.agent import Agent

        # Load delegator
        result = await self.session.execute(select(Agent).where(Agent.id == delegator_agent_id))
        delegator = result.scalar_one_or_none()
        if delegator is None or not delegator.is_active():
            raise AuthenticationError("Delegator agent not found or inactive")

        # Load delegate
        result = await self.session.execute(select(Agent).where(Agent.id == delegate_agent_id))
        delegate = result.scalar_one_or_none()
        if delegate is None or not delegate.is_active():
            raise AuthenticationError("Delegate agent not found or inactive")

        # Compute delegator's effective scopes and chain depth
        effective_scopes, chain_depth = await self.get_effective_scopes_and_depth(
            delegator_agent_id
        )

        # Validate scope attenuation (supports wildcard patterns like 'files.*')
        if effective_scopes is not None:
            effective_set = set(effective_scopes)
            escalated = {s for s in scopes if not _scope_is_delegatable(s, effective_set)}
            if escalated:
                raise ValueError(f"Scope escalation: delegator does not hold scopes {escalated}")

        # Validate chain depth
        new_chain_depth = chain_depth + 1
        if new_chain_depth > max_chain_depth:
            raise ValueError(f"Chain depth {new_chain_depth} exceeds maximum {max_chain_depth}")

        delegation = Delegation(
            delegator_agent_id=delegator_agent_id,
            delegate_agent_id=delegate_agent_id,
            scopes=scopes,
            constraints=constraints or {},
            chain_depth=new_chain_depth,
            max_chain_depth=max_chain_depth,
            expires_at=expires_at,
        )
        self.session.add(delegation)
        await self.session.commit()
        await self.session.refresh(delegation)

        logger.info(
            "Delegation created",
            delegation_id=str(delegation.id),
            delegator=str(delegator_agent_id),
            delegate=str(delegate_agent_id),
            scopes=scopes,
            chain_depth=new_chain_depth,
        )
        return delegation

    async def get_effective_scopes_and_depth(self, agent_id: UUID) -> tuple[list[str] | None, int]:
        """
        Compute an agent's effective scopes and current chain depth.

        Root agents (no active incoming delegations) have unrestricted scopes
        (returns None) and depth 0.
        """
        # Find the most recent active incoming delegation for this agent
        result = await self.session.execute(
            select(Delegation)
            .where(
                Delegation.delegate_agent_id == agent_id,
                Delegation.revoked_at.is_(None),
            )
            .order_by(Delegation.created_at.desc())
        )
        delegations = list(result.scalars().all())

        active = [d for d in delegations if d.is_active()]
        if not active:
            # Root agent — no scope restriction
            return None, 0

        # Intersect all active incoming delegations for conservative effective scopes
        scope_sets = [set(d.scopes) for d in active]
        effective = scope_sets[0]
        for s in scope_sets[1:]:
            effective = effective.intersection(s)

        max_depth = max(d.chain_depth for d in active)
        return sorted(effective), max_depth

    async def get_delegation_chain(self, delegation_id: UUID) -> list[Delegation]:
        """
        Traverse the delegation chain upward from the given delegation.

        Uses a single recursive CTE to fetch the entire chain in one query
        (O(1) round-trips vs the previous O(n) sequential approach).
        Results are cached in Redis for ``_CHAIN_CACHE_TTL`` seconds and
        invalidated on revocation or new delegation creation.
        """
        cache_key = f"{_CHAIN_CACHE_PREFIX}{delegation_id}"

        # --- cache read ---
        try:
            from agentauth.core.redis import get_redis_client

            redis_client = get_redis_client()
            cached_raw = await redis_client.get(cache_key)
            if cached_raw is not None:
                cached_ids = json.loads(cached_raw)
                result = await self.session.execute(
                    select(Delegation).where(Delegation.id.in_(cached_ids))
                )
                by_id = {str(d.id): d for d in result.scalars().all()}
                return [by_id[sid] for sid in cached_ids if sid in by_id]
        except Exception as exc:
            logger.debug("delegation_chain_cache_read_failed", error=str(exc))

        # --- single recursive CTE ---
        cte_sql = text("""
            WITH RECURSIVE chain AS (
                -- anchor: the requested delegation
                SELECT d.id, d.delegator_agent_id, d.delegate_agent_id,
                       d.scopes, d.constraints, d.chain_depth, d.max_chain_depth,
                       d.expires_at, d.revoked_at, d.created_at, d.updated_at
                FROM delegations d
                WHERE d.id = :delegation_id

                UNION ALL

                -- walk upward: find the active delegation whose delegate is
                -- the current row's delegator
                SELECT p.id, p.delegator_agent_id, p.delegate_agent_id,
                       p.scopes, p.constraints, p.chain_depth, p.max_chain_depth,
                       p.expires_at, p.revoked_at, p.created_at, p.updated_at
                FROM delegations p
                INNER JOIN chain c ON p.delegate_agent_id = c.delegator_agent_id
                WHERE p.revoked_at IS NULL
                  AND (p.expires_at IS NULL OR p.expires_at > now())
            )
            SELECT id FROM chain ORDER BY chain_depth ASC
        """)
        id_result = await self.session.execute(cte_sql, {"delegation_id": delegation_id})
        ordered_ids = [row[0] for row in id_result.fetchall()]

        if not ordered_ids:
            return []

        # Fetch full ORM objects in one IN query
        obj_result = await self.session.execute(
            select(Delegation).where(Delegation.id.in_(ordered_ids))
        )
        by_id = {d.id: d for d in obj_result.scalars().all()}
        chain = [by_id[oid] for oid in ordered_ids if oid in by_id]

        # --- cache write ---
        try:
            await redis_client.set(  # type: ignore[possibly-undefined]
                cache_key,
                json.dumps([str(oid) for oid in ordered_ids]),
                ex=_CHAIN_CACHE_TTL,
            )
        except Exception as exc:
            logger.debug("delegation_chain_cache_write_failed", error=str(exc))

        return chain

    async def revoke_delegation(self, delegation_id: UUID, cascade: bool = True) -> int:
        """
        Revoke a delegation and optionally all downstream delegations.

        Returns the number of delegations revoked.
        """
        now = datetime.now(UTC)
        revoked_count = 0

        result = await self.session.execute(
            select(Delegation).where(Delegation.id == delegation_id)
        )
        delegation = result.scalar_one_or_none()
        if delegation is None:
            return 0

        delegation.revoked_at = now
        revoked_count += 1

        if cascade:
            revoked_count += await self._cascade_revoke(delegation.delegate_agent_id, now)

        await self.session.commit()

        # Invalidate chain cache for the revoked delegation
        await self._invalidate_chain_cache(delegation_id)

        logger.info(
            "Delegation revoked",
            delegation_id=str(delegation_id),
            cascade=cascade,
            total_revoked=revoked_count,
        )
        return revoked_count

    async def _invalidate_chain_cache(self, delegation_id: UUID) -> None:
        """Remove the cached delegation chain for the given delegation ID."""
        try:
            from agentauth.core.redis import get_redis_client

            redis_client = get_redis_client()
            await redis_client.delete(f"{_CHAIN_CACHE_PREFIX}{delegation_id}")
        except Exception as exc:
            logger.debug("delegation_chain_cache_invalidation_failed", error=str(exc))

    async def _cascade_revoke(self, agent_id: UUID, now: datetime) -> int:
        """Revoke all downstream delegations using iterative BFS to avoid N+1."""
        count = 0
        queue = [agent_id]

        while queue:
            current_ids = queue
            queue = []

            result = await self.session.execute(
                select(Delegation).where(
                    Delegation.delegator_agent_id.in_(current_ids),
                    Delegation.revoked_at.is_(None),
                )
            )
            downstream = list(result.scalars().all())

            for d in downstream:
                d.revoked_at = now
                count += 1
                queue.append(d.delegate_agent_id)

        return count
