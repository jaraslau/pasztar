"""client encryption key

Revision ID: 20260729_0002
Revises: 20260728_0001
Create Date: 2026-07-29 00:00:00
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20260729_0002"
down_revision: str | Sequence[str] | None = "20260728_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("clients")
    }
    if "encryption_public_key" not in columns:
        op.add_column(
            "clients",
            sa.Column("encryption_public_key", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("clients")
    }
    if "encryption_public_key" in columns:
        op.drop_column("clients", "encryption_public_key")
