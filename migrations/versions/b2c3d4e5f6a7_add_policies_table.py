"""add_policies_table

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-07 10:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'policies',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_by_agent_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('effect', sa.String(16), nullable=False, server_default='allow'),
        sa.Column('subjects', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('resources', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('actions', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('conditions', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_agent_id'], ['agents.id'], ondelete='CASCADE',
                                name='fk_policies_created_by_agent_id_agents'),
        sa.PrimaryKeyConstraint('id', name='pk_policies'),
    )
    op.create_index('ix_policies_id', 'policies', ['id'], unique=False)
    op.create_index('ix_policies_created_by_agent_id', 'policies', ['created_by_agent_id'], unique=False)
    op.create_index('ix_policies_priority', 'policies', ['priority'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_policies_priority', table_name='policies')
    op.drop_index('ix_policies_created_by_agent_id', table_name='policies')
    op.drop_index('ix_policies_id', table_name='policies')
    op.drop_table('policies')
