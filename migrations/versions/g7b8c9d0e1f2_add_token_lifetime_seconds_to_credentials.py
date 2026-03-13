"""add_token_lifetime_seconds_to_credentials

Revision ID: g7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-03-14 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "g7b8c9d0e1f2"
down_revision: str | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column("token_lifetime_seconds", sa.INTEGER(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("credentials", "token_lifetime_seconds")
