"""add_delegations_table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-03-07 10:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'delegations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('delegator_agent_id', sa.UUID(), nullable=False),
        sa.Column('delegate_agent_id', sa.UUID(), nullable=False),
        sa.Column('scopes', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('constraints', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('chain_depth', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_chain_depth', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['delegator_agent_id'], ['agents.id'], ondelete='CASCADE',
            name='fk_delegations_delegator_agent_id_agents',
        ),
        sa.ForeignKeyConstraint(
            ['delegate_agent_id'], ['agents.id'], ondelete='CASCADE',
            name='fk_delegations_delegate_agent_id_agents',
        ),
        sa.PrimaryKeyConstraint('id', name='pk_delegations'),
    )
    op.create_index('ix_delegations_id', 'delegations', ['id'], unique=False)
    op.create_index('ix_delegations_delegator_agent_id', 'delegations', ['delegator_agent_id'], unique=False)
    op.create_index('ix_delegations_delegate_agent_id', 'delegations', ['delegate_agent_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_delegations_delegate_agent_id', table_name='delegations')
    op.drop_index('ix_delegations_delegator_agent_id', table_name='delegations')
    op.drop_index('ix_delegations_id', table_name='delegations')
    op.drop_table('delegations')
