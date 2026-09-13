"""Bootstrap admission and single-use invitations."""

import sqlalchemy as sa
from alembic import op

revision = "20260913_0005"
down_revision = "20260802_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bootstrap_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("consumed", sa.Boolean(), nullable=False),
        sa.CheckConstraint("id = 1"),
    )
    op.execute(
        sa.text(
            "INSERT INTO bootstrap_state (id, consumed) "
            "SELECT 1, EXISTS (SELECT 1 FROM clients)"
        )
    )
    op.create_table(
        "invitations",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "creator_id", sa.String(80), sa.ForeignKey("clients.id"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("redeemed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("invitations")
    op.drop_table("bootstrap_state")
