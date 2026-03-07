"""add_audit_gin_index

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-07 10:15:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # GIN index on audit_events.metadata JSONB for efficient JSON querying
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_events_metadata_gin "
        "ON audit_events USING gin (metadata)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_audit_events_metadata_gin")
