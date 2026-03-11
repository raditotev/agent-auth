"""Identity service for agent registration and management."""

from uuid import UUID

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from agentauth.models.agent import Agent, AgentStatus, TrustLevel
from agentauth.schemas.agent import AgentBootstrapCreate, AgentCreate, AgentUpdate

logger = structlog.get_logger()


class IdentityService:
    """Service for managing agent identities."""

    def __init__(self, session: AsyncSession):
        """Initialize service with database session."""
        self.session = session

    async def create_root_agent(self, data: AgentBootstrapCreate) -> Agent:
        """
        Create a root agent (self-registration).

        Root agents have:
        - parent_agent_id = None
        - trust_level = ROOT
        - No parent validation needed
        """
        agent = Agent(
            parent_agent_id=None,
            name=data.name,
            agent_type=data.agent_type,
            description=data.description,
            homepage_url=str(data.homepage_url) if data.homepage_url else None,
            public_key=data.public_key,
            trust_level=TrustLevel.ROOT,
            status=AgentStatus.ACTIVE,
            max_child_depth=data.max_child_depth,
            agent_metadata=data.agent_metadata or {},
        )

        self.session.add(agent)
        await self.session.flush()
        await self.session.refresh(agent)

        logger.info(
            "Root agent created",
            agent_id=str(agent.id),
            name=agent.name,
            agent_type=agent.agent_type.value,
        )

        return agent

    async def create_child_agent(self, data: AgentCreate) -> Agent:
        """
        Create a child agent under a parent.

        Validates:
        - Parent exists and is active
        - Agent name is unique within parent's scope
        - Parent has not exceeded max_child_depth
        """
        # Load parent agent
        parent = await self.get_agent_by_id(data.parent_agent_id)
        if not parent:
            raise ValueError(f"Parent agent {data.parent_agent_id} not found")

        if not parent.is_active():
            raise ValueError(f"Parent agent {data.parent_agent_id} is not active")

        # Check for duplicate name under same parent
        stmt = select(Agent).where(
            Agent.parent_agent_id == data.parent_agent_id,
            Agent.name == data.name,
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            raise ValueError(
                f"Agent with name '{data.name}' already exists under parent {data.parent_agent_id}"
            )

        # Compute actual depth from root by walking up the parent chain
        depth = 0
        current = parent
        visited: set = {current.id}
        while current.parent_agent_id is not None:
            result = await self.session.execute(
                select(Agent).where(Agent.id == current.parent_agent_id)
            )
            ancestor = result.scalar_one_or_none()
            if ancestor is None or ancestor.id in visited:
                break
            visited.add(ancestor.id)
            depth += 1
            current = ancestor

        # Check the immediate parent allows children and depth hasn't exceeded root limit
        if parent.max_child_depth < 1:
            raise ValueError(
                f"Parent agent {data.parent_agent_id} cannot have child agents "
                f"(max_child_depth={parent.max_child_depth})"
            )

        # Validate against root agent's max_child_depth
        root = current
        if depth + 1 > root.max_child_depth:
            raise ValueError(
                f"Creating this child would exceed the root agent's max depth of "
                f"{root.max_child_depth} (current depth: {depth})"
            )

        # Create child agent
        agent = Agent(
            parent_agent_id=data.parent_agent_id,
            name=data.name,
            agent_type=data.agent_type,
            description=data.description,
            homepage_url=str(data.homepage_url) if data.homepage_url else None,
            public_key=data.public_key,
            trust_level=TrustLevel.DELEGATED,  # Child agents are delegated trust
            status=AgentStatus.ACTIVE,
            max_child_depth=min(
                data.max_child_depth, parent.max_child_depth - 1
            ),  # Attenuate max depth
            agent_metadata=data.agent_metadata or {},
        )

        self.session.add(agent)
        await self.session.flush()
        await self.session.refresh(agent)

        logger.info(
            "Child agent created",
            agent_id=str(agent.id),
            name=agent.name,
            parent_agent_id=str(agent.parent_agent_id),
            agent_type=agent.agent_type.value,
        )

        return agent

    async def get_agent_by_id(self, agent_id: UUID) -> Agent | None:
        """Get agent by ID."""
        stmt = select(Agent).where(Agent.id == agent_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_subtree_agent_ids(self, root_id: UUID) -> list[UUID]:
        """
        Return all agent IDs in the subtree rooted at root_id (inclusive).

        Uses a recursive CTE to efficiently traverse the self-referencing
        parent_agent_id hierarchy.
        """
        sql = text("""
            WITH RECURSIVE subtree AS (
                SELECT id FROM agents WHERE id = :root_id
                UNION ALL
                SELECT a.id FROM agents a
                INNER JOIN subtree s ON a.parent_agent_id = s.id
            )
            SELECT id FROM subtree
        """)
        result = await self.session.execute(sql, {"root_id": root_id})
        return [row[0] for row in result.fetchall()]

    async def list_agents(
        self,
        parent_agent_id: UUID | None = None,
        status: AgentStatus | None = None,
        limit: int = 50,
        offset: int = 0,
        subtree_ids: list[UUID] | None = None,
    ) -> list[Agent]:
        """
        List agents with optional filtering.

        Args:
            parent_agent_id: Filter by parent agent
            status: Filter by status
            limit: Maximum number of results
            offset: Offset for pagination
            subtree_ids: If provided, only return agents whose IDs are in this set
        """
        stmt = select(Agent).order_by(Agent.created_at.desc())

        # Subtree scope — restricts results to the caller's hierarchy
        if subtree_ids is not None:
            stmt = stmt.where(Agent.id.in_(subtree_ids))

        # Filter by parent
        if parent_agent_id is not None:
            stmt = stmt.where(Agent.parent_agent_id == parent_agent_id)

        # Filter by status
        if status is not None:
            stmt = stmt.where(Agent.status == status)

        # Pagination
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_agent_children(self, agent_id: UUID) -> list[Agent]:
        """Get all direct children of an agent."""
        stmt = (
            select(Agent).where(Agent.parent_agent_id == agent_id).order_by(Agent.created_at.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_agent(self, agent_id: UUID, data: AgentUpdate) -> Agent | None:
        """Update agent details."""
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            return None

        # Update only provided fields from the allowed set
        _updatable_fields = {
            "name",
            "description",
            "homepage_url",
            "public_key",
            "max_child_depth",
            "agent_metadata",
        }
        update_data = data.model_dump(exclude_unset=True, by_alias=False)
        for key, value in update_data.items():
            if key not in _updatable_fields:
                continue
            if key == "homepage_url" and value is not None:
                value = str(value)
            setattr(agent, key, value)

        await self.session.flush()
        await self.session.refresh(agent)

        logger.info(
            "Agent updated",
            agent_id=str(agent.id),
            updated_fields=list(update_data.keys()),
        )

        return agent

    async def deactivate_agent(self, agent_id: UUID) -> Agent | None:
        """
        Deactivate an agent (soft delete).

        Sets status to SUSPENDED and records deactivated_at timestamp.
        """
        agent = await self.get_agent_by_id(agent_id)
        if not agent:
            return None

        agent.deactivate()
        await self.session.flush()
        await self.session.refresh(agent)

        logger.info(
            "Agent deactivated",
            agent_id=str(agent.id),
            name=agent.name,
        )

        return agent

    async def get_agent_with_credentials(self, agent_id: UUID) -> Agent | None:
        """Get agent with credentials eagerly loaded."""
        stmt = select(Agent).where(Agent.id == agent_id).options(selectinload(Agent.credentials))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
