"""Authorization service — policy evaluation engine."""

from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentauth.config import settings
from agentauth.models.policy import Policy, PolicyEffect
from agentauth.schemas.policy import PolicyEvaluateResponse

logger = structlog.get_logger()


class AuthorizationService:
    """
    Policy evaluation engine using deny-overrides combining algorithm.

    Evaluation order:
    1. Load all enabled policies, ordered by priority (highest first).
    2. Check each policy in order:
       - If a DENY policy matches → immediately deny (deny-overrides).
       - If an ALLOW policy matches → record it but continue checking for denies.
    3. If at least one ALLOW matched and no DENY matched → allow.
    4. If no policy matched → deny (default-deny).
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate(
        self,
        agent_id: UUID,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyEvaluateResponse:
        """
        Evaluate whether an agent is permitted to perform an action on a resource.

        Args:
            agent_id: UUID of the requesting agent
            action: Action being attempted (e.g. 'read', 'write', 'delete')
            resource: Resource path or identifier (e.g. '/api/v1/agents')
            context: Additional context (IP, time, etc.)

        Returns:
            PolicyEvaluateResponse with decision and matching policy details
        """
        ctx = context or {}

        # Try cache first
        cached = await self._get_cached_decision(agent_id, action, resource, ctx)
        if cached is not None:
            return cached

        policies = await self._load_policies(agent_id)

        allow_match: Policy | None = None
        deny_match: Policy | None = None

        for policy in policies:
            if not self._policy_matches(policy, agent_id, action, resource, ctx):
                continue

            if policy.effect == PolicyEffect.DENY:
                deny_match = policy
                break  # deny-overrides: stop immediately
            elif policy.effect == PolicyEffect.ALLOW and allow_match is None:
                allow_match = policy
                # Don't break — keep looking for a DENY with higher priority

        if deny_match is not None:
            result = PolicyEvaluateResponse(
                allowed=False,
                effect="deny",
                matching_policy_id=deny_match.id,
                matching_policy_name=deny_match.name,
                reason=f"Denied by policy '{deny_match.name}' (id={deny_match.id})",
            )
        elif allow_match is not None:
            result = PolicyEvaluateResponse(
                allowed=True,
                effect="allow",
                matching_policy_id=allow_match.id,
                matching_policy_name=allow_match.name,
                reason=f"Allowed by policy '{allow_match.name}' (id={allow_match.id})",
            )
        else:
            result = PolicyEvaluateResponse(
                allowed=False,
                effect="deny",
                matching_policy_id=None,
                matching_policy_name=None,
                reason="No matching policy found — default deny",
            )

        logger.info(
            "Policy evaluation complete",
            agent_id=str(agent_id),
            action=action,
            resource=resource,
            allowed=result.allowed,
            reason=result.reason,
        )

        await self._cache_decision(agent_id, action, resource, ctx, result)
        return result

    async def _load_policies(self, agent_id: UUID) -> list[Policy]:
        """Load enabled policies scoped to the given agent's trust chain.

        Only policies whose creator is an ancestor of (or is) the requesting
        agent are loaded. This prevents policies from one root-agent tree from
        affecting agents in a different tree.
        """
        # Walk from agent_id up to the root, collecting every ancestor ID.
        ancestor_sql = text("""
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_agent_id FROM agents WHERE id = :agent_id
                UNION ALL
                SELECT a.id, a.parent_agent_id
                FROM agents a
                INNER JOIN ancestors anc ON a.id = anc.parent_agent_id
            )
            SELECT id FROM ancestors
        """)
        ancestor_result = await self.session.execute(ancestor_sql, {"agent_id": agent_id})
        ancestor_ids = [row[0] for row in ancestor_result.fetchall()]

        if not ancestor_ids:
            return []

        result = await self.session.execute(
            select(Policy)
            .where(Policy.enabled.is_(True))
            .where(Policy.created_by_agent_id.in_(ancestor_ids))
            .order_by(Policy.priority.desc())
        )
        return list(result.scalars().all())

    def _policy_matches(
        self,
        policy: Policy,
        agent_id: UUID,
        action: str,
        resource: str,
        context: dict[str, Any],
    ) -> bool:
        """Check if a policy applies to the given agent/action/resource."""
        return (
            self._matches_subjects(policy.subjects, agent_id)
            and self._matches_actions(policy.actions, action)
            and self._matches_resources(policy.resources, resource)
            and self._matches_conditions(policy.conditions, context)
        )

    @staticmethod
    def _matches_subjects(subjects: dict, agent_id: UUID) -> bool:
        """
        Match agent against policy subjects.

        subjects dict can contain:
        - "agent_ids": list of explicit UUID strings
        - "wildcard": true (matches any agent)
        - (empty dict matches any agent — open policy)
        """
        if not subjects:
            return True  # empty subjects = applies to everyone

        if subjects.get("wildcard"):
            return True

        agent_ids = subjects.get("agent_ids", [])
        return str(agent_id) in agent_ids

    @staticmethod
    def _matches_actions(policy_actions: list[str], action: str) -> bool:
        """Match the requested action against the policy's action list."""
        if not policy_actions:
            return True  # no action restriction = matches all
        return action in policy_actions or "*" in policy_actions

    @staticmethod
    def _matches_resources(resources: dict, resource: str) -> bool:
        """
        Match the requested resource against policy resources.

        resources dict can contain:
        - "paths": list of path strings (supports '*' suffix wildcard)
        - "wildcard": true (matches any resource)
        - (empty dict matches any resource)
        """
        if not resources:
            return True

        if resources.get("wildcard"):
            return True

        paths = resources.get("paths", [])
        for pattern in paths:
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                if resource.startswith(prefix):
                    return True
            elif pattern == resource:
                return True

        return False

    @staticmethod
    def _matches_conditions(conditions: dict, context: dict[str, Any]) -> bool:
        """
        Evaluate optional conditions.

        Currently supports:
        - "ip_allowlist": list of IP strings — context must have "ip" key
        (Extensible for time windows, rate limits, etc.)
        """
        if not conditions:
            return True

        if "ip_allowlist" in conditions:
            client_ip = context.get("ip")
            if client_ip not in conditions["ip_allowlist"]:
                return False

        return True

    @staticmethod
    def _context_hash(context: dict) -> str:
        """Generate a short hash of the context for cache key inclusion."""
        import hashlib

        ctx_str = str(sorted(context.items())) if context else ""
        return hashlib.md5(ctx_str.encode()).hexdigest()[:8]

    async def _get_cached_decision(
        self,
        agent_id: UUID,
        action: str,
        resource: str,
        context: dict | None = None,
    ) -> PolicyEvaluateResponse | None:
        """Try to retrieve a cached authorization decision from Redis."""
        try:
            from agentauth.core.redis import get_redis_client

            redis_client = get_redis_client()
            ctx_hash = self._context_hash(context) if context else "none"
            cache_key = f"authz:{agent_id}:{action}:{resource}:{ctx_hash}"
            cached_json = await redis_client.get_json(cache_key)
            if cached_json is not None:
                logger.debug("Authorization decision cache hit", cache_key=cache_key)
                return PolicyEvaluateResponse(**cached_json)
        except Exception as e:
            logger.debug("Authorization cache read failed", error=str(e))
        return None

    async def _cache_decision(
        self,
        agent_id: UUID,
        action: str,
        resource: str,
        context: dict | None,
        result: PolicyEvaluateResponse,
    ) -> None:
        """Cache the authorization decision in Redis."""
        try:
            from agentauth.core.redis import get_redis_client

            redis_client = get_redis_client()
            ctx_hash = self._context_hash(context) if context else "none"
            cache_key = f"authz:{agent_id}:{action}:{resource}:{ctx_hash}"
            await redis_client.set_json(
                cache_key,
                result.model_dump(mode="json"),
                ex=settings.policy_cache_ttl_seconds,
            )
        except Exception as e:
            logger.debug("Authorization cache write failed", error=str(e))
