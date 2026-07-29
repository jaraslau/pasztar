"""initial

Revision ID: 20260728_0001
Revises:
Create Date: 2026-07-28 00:00:00
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20260728_0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "clients" not in tables:
        op.create_table(
            "clients",
            sa.Column("id", sa.String(length=80), nullable=False),
            sa.Column("display_name", sa.String(length=120), nullable=False),
            sa.Column("public_key", sa.Text(), nullable=False),
            sa.Column("encryption_public_key", sa.Text(), nullable=False),
            sa.Column("fingerprint", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    if "messages" not in tables:
        op.create_table(
            "messages",
            sa.Column("id", sa.String(length=80), nullable=False),
            sa.Column("sender_id", sa.String(length=80), nullable=False),
            sa.Column("recipient_id", sa.String(length=80), nullable=False),
            sa.Column("ciphertext", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["recipient_id"], ["clients.id"]),
            sa.ForeignKeyConstraint(["sender_id"], ["clients.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_messages_recipient_created",
            "messages",
            ["recipient_id", "created_at"],
        )
        op.create_index(
            "ix_messages_sender_created",
            "messages",
            ["sender_id", "created_at"],
        )
    if "nonces" not in tables:
        op.create_table(
            "nonces",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("client_id", sa.String(length=80), nullable=False),
            sa.Column("nonce", sa.String(length=120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["client_id"], ["clients.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("client_id", "nonce"),
        )
        op.create_index("ix_nonces_created", "nonces", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_nonces_created", table_name="nonces")
    op.drop_table("nonces")
    op.drop_index("ix_messages_sender_created", table_name="messages")
    op.drop_index("ix_messages_recipient_created", table_name="messages")
    op.drop_table("messages")
    op.drop_table("clients")
