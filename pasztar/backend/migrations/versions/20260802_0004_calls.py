"""calls

Revision ID: 20260802_0004
Revises: 20260802_0003
Create Date: 2026-08-02 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260802_0004"
down_revision: str | Sequence[str] | None = "20260802_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "calls" not in tables:
        op.create_table(
            "calls",
            sa.Column("id", sa.String(length=80), nullable=False),
            sa.Column("client_a_id", sa.String(length=80), nullable=False),
            sa.Column("client_b_id", sa.String(length=80), nullable=False),
            sa.Column("started_by_id", sa.String(length=80), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["client_a_id"], ["clients.id"]),
            sa.ForeignKeyConstraint(["client_b_id"], ["clients.id"]),
            sa.ForeignKeyConstraint(["started_by_id"], ["clients.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_calls_pair_active",
            "calls",
            ["client_a_id", "client_b_id", "ended_at"],
        )
    if "call_participants" not in tables:
        op.create_table(
            "call_participants",
            sa.Column("call_id", sa.String(length=80), nullable=False),
            sa.Column("client_id", sa.String(length=80), nullable=False),
            sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["call_id"], ["calls.id"]),
            sa.ForeignKeyConstraint(["client_id"], ["clients.id"]),
            sa.PrimaryKeyConstraint("call_id", "client_id"),
        )
        op.create_index(
            "ix_call_participants_last_seen",
            "call_participants",
            ["last_seen_at"],
        )
    if "call_signals" not in tables:
        op.create_table(
            "call_signals",
            sa.Column("id", sa.String(length=80), nullable=False),
            sa.Column("call_id", sa.String(length=80), nullable=False),
            sa.Column("sender_id", sa.String(length=80), nullable=False),
            sa.Column("recipient_id", sa.String(length=80), nullable=False),
            sa.Column("ciphertext", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["call_id"], ["calls.id"]),
            sa.ForeignKeyConstraint(["sender_id"], ["clients.id"]),
            sa.ForeignKeyConstraint(["recipient_id"], ["clients.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_call_signals_recipient_created",
            "call_signals",
            ["recipient_id", "created_at"],
        )


def downgrade() -> None:
    op.drop_index("ix_call_signals_recipient_created", table_name="call_signals")
    op.drop_table("call_signals")
    op.drop_index("ix_call_participants_last_seen", table_name="call_participants")
    op.drop_table("call_participants")
    op.drop_index("ix_calls_pair_active", table_name="calls")
    op.drop_table("calls")
