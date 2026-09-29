"""
Add recon source configuration table.

Revision ID: 20260313_recon_sources
Revises: 20260313_endpoint_lifecycle_status
Create Date: 2026-03-13 00:00:09.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_recon_sources"
down_revision = "20260313_endpoint_lifecycle_status"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "recon_sources",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("interval_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(20), nullable=False, server_default="NEVER"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", "name", name="uq_recon_source_name"),
    )
    op.create_index("idx_recon_sources_account", "recon_sources", ["account_id"])


def downgrade():
    op.drop_index("idx_recon_sources_account", table_name="recon_sources")
    op.drop_table("recon_sources")
