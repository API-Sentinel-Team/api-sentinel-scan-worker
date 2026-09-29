"""
Add warm export cursor table for ClickHouse export tracking.

Revision ID: 20260313_warm_export_cursors
Revises: 20260313_ml_tables
Create Date: 2026-03-13 00:00:06.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_warm_export_cursors"
down_revision = "20260313_ml_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "warm_export_cursors",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("table_name", sa.String(100), nullable=False),
        sa.Column("last_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_id", sa.String(36), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "table_name", name="uq_warm_export_cursor"),
    )
    op.create_index("idx_warm_export_cursors_account", "warm_export_cursors", ["account_id"])


def downgrade():
    op.drop_index("idx_warm_export_cursors_account", table_name="warm_export_cursors")
    op.drop_table("warm_export_cursors")
