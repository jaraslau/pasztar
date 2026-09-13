"""Index identity activity for retention cleanup."""

from alembic import op

revision = "20260913_0006"
down_revision = "20260913_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_clients_last_seen", "clients", ["last_seen"])


def downgrade() -> None:
    op.drop_index("ix_clients_last_seen", table_name="clients")
