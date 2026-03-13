"""Enforce unique agent names within trust scope

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-03-13 00:00:00.000000

IMPORTANT — before applying this migration in an existing environment:
  Run the following query to find name conflicts that will block the migration:

  -- Duplicate root agent names:
  SELECT name, COUNT(*) FROM agents
  WHERE parent_agent_id IS NULL
  GROUP BY name HAVING COUNT(*) > 1;

  -- Duplicate child agent names per parent:
  SELECT parent_agent_id, name, COUNT(*) FROM agents
  WHERE parent_agent_id IS NOT NULL
  GROUP BY parent_agent_id, name HAVING COUNT(*) > 1;

  Resolve any duplicates (rename or remove agents) before running upgrade.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add partial unique indexes for agent name uniqueness within trust scope."""
    # De-duplicate root agent names: keep oldest (lowest uuid7), rename the rest
    op.execute(
        """
        WITH duplicates AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY name ORDER BY id) AS rn
            FROM agents
            WHERE parent_agent_id IS NULL
        )
        UPDATE agents
        SET name = agents.name || '_dup_' || SUBSTRING(agents.id::text, 1, 8)
        FROM duplicates
        WHERE agents.id = duplicates.id AND duplicates.rn > 1
        """
    )
    # De-duplicate child agent names per parent: keep oldest, rename the rest
    op.execute(
        """
        WITH duplicates AS (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY parent_agent_id, name ORDER BY id) AS rn
            FROM agents
            WHERE parent_agent_id IS NOT NULL
        )
        UPDATE agents
        SET name = agents.name || '_dup_' || SUBSTRING(agents.id::text, 1, 8)
        FROM duplicates
        WHERE agents.id = duplicates.id AND duplicates.rn > 1
        """
    )
    # Unique root agent names (parent_agent_id IS NULL)
    op.execute(
        """
        CREATE UNIQUE INDEX uq_agents_root_name
        ON agents (name)
        WHERE parent_agent_id IS NULL
        """
    )
    # Unique child agent names per parent (parent_agent_id IS NOT NULL)
    op.execute(
        """
        CREATE UNIQUE INDEX uq_agents_child_name
        ON agents (parent_agent_id, name)
        WHERE parent_agent_id IS NOT NULL
        """
    )


def downgrade() -> None:
    """Remove partial unique indexes for agent name uniqueness."""
    op.execute("DROP INDEX IF EXISTS uq_agents_root_name")
    op.execute("DROP INDEX IF EXISTS uq_agents_child_name")
