"""add_webhook_tables

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-07 10:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'webhook_subscriptions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('agent_id', sa.UUID(), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('secret', sa.Text(), nullable=False),
        sa.Column('events', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['agent_id'], ['agents.id'], ondelete='CASCADE',
            name='fk_webhook_subscriptions_agent_id_agents',
        ),
        sa.PrimaryKeyConstraint('id', name='pk_webhook_subscriptions'),
    )
    op.create_index('ix_webhook_subscriptions_id', 'webhook_subscriptions', ['id'])
    op.create_index('ix_webhook_subscriptions_agent_id', 'webhook_subscriptions', ['agent_id'])

    op.create_table(
        'webhook_delivery_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('subscription_id', sa.UUID(), nullable=False),
        sa.Column('event_type', sa.String(255), nullable=False),
        sa.Column('payload', postgresql.JSONB(), nullable=False),
        sa.Column('attempt', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['subscription_id'], ['webhook_subscriptions.id'], ondelete='CASCADE',
            name='fk_webhook_delivery_logs_subscription_id_webhook_subscriptions',
        ),
        sa.PrimaryKeyConstraint('id', name='pk_webhook_delivery_logs'),
    )
    op.create_index('ix_webhook_delivery_logs_id', 'webhook_delivery_logs', ['id'])
    op.create_index('ix_webhook_delivery_logs_subscription_id', 'webhook_delivery_logs', ['subscription_id'])


def downgrade() -> None:
    op.drop_index('ix_webhook_delivery_logs_subscription_id', table_name='webhook_delivery_logs')
    op.drop_index('ix_webhook_delivery_logs_id', table_name='webhook_delivery_logs')
    op.drop_table('webhook_delivery_logs')
    op.drop_index('ix_webhook_subscriptions_agent_id', table_name='webhook_subscriptions')
    op.drop_index('ix_webhook_subscriptions_id', table_name='webhook_subscriptions')
    op.drop_table('webhook_subscriptions')
