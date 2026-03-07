"""add_scopes_table

Revision ID: a1b2c3d4e5f6
Revises: bede3c340be9
Create Date: 2026-03-07 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'bede3c340be9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scopes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('category', sa.String(128), nullable=False, server_default='general'),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_scopes'),
        sa.UniqueConstraint('name', name='uq_scopes_name'),
    )
    op.create_index('ix_scopes_id', 'scopes', ['id'], unique=False)
    op.create_index('ix_scopes_name', 'scopes', ['name'], unique=False)
    op.create_index('ix_scopes_category', 'scopes', ['category'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_scopes_category', table_name='scopes')
    op.drop_index('ix_scopes_name', table_name='scopes')
    op.drop_index('ix_scopes_id', table_name='scopes')
    op.drop_table('scopes')
