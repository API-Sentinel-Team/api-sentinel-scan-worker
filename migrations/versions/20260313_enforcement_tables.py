"""
Add enforcement tables (endpoint blocks, rate limit overrides).

Revision ID: 20260313_enforcement_tables
Revises: 20260313_analytics_and_evidence_details
Create Date: 2026-03-13 00:00:04.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_enforcement_tables"
down_revision = "20260313_analytics_and_evidence_details"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "endpoint_blocks",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("blocked_by", sa.String(50), nullable=False, server_default="AUTO"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_endpoint_blocks_account", "endpoint_blocks", ["account_id"])
    op.create_index("idx_endpoint_blocks_endpoint", "endpoint_blocks", ["endpoint_id"])

    op.create_table(
        "rate_limit_overrides",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=False),
        sa.Column("limit_rpm", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("duration_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_rate_limit_account", "rate_limit_overrides", ["account_id"])
    op.create_index("idx_rate_limit_endpoint", "rate_limit_overrides", ["endpoint_id"])


def downgrade():
    op.drop_index("idx_rate_limit_endpoint", table_name="rate_limit_overrides")
    op.drop_index("idx_rate_limit_account", table_name="rate_limit_overrides")
    op.drop_table("rate_limit_overrides")

    op.drop_index("idx_endpoint_blocks_endpoint", table_name="endpoint_blocks")
    op.drop_index("idx_endpoint_blocks_account", table_name="endpoint_blocks")
    op.drop_table("endpoint_blocks")
