"""message reply target

Revision ID: 20260802_0003
Revises: 20260729_0002
Create Date: 2026-08-02 00:00:00
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20260802_0003"
down_revision: str | Sequence[str] | None = "20260729_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("messages")
    }
    if "reply_to_id" not in columns:
        op.add_column("messages", sa.Column("reply_to_id", sa.String(length=80)))


def downgrade() -> None:
    columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("messages")
    }
    if "reply_to_id" in columns:
        op.drop_column("messages", "reply_to_id")
