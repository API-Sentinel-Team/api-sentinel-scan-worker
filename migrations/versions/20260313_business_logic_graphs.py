"""
Add business logic graph tables.

Revision ID: 20260313_business_logic_graphs
Revises: 20260313_detection_actor_profiles
Create Date: 2026-03-13 00:00:03.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_business_logic_graphs"
down_revision = "20260313_detection_actor_profiles"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "business_logic_graphs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("nodes_json", sa.JSON(), nullable=True),
        sa.Column("edges_json", sa.JSON(), nullable=True),
        sa.Column("built_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_blg_account", "business_logic_graphs", ["account_id"])

    op.create_table(
        "business_logic_violations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("from_path", sa.String(), nullable=True),
        sa.Column("to_path", sa.String(), nullable=True),
        sa.Column("violation_type", sa.String(100), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_blg_violations_account", "business_logic_violations", ["account_id"])
    op.create_index("idx_blg_violations_actor", "business_logic_violations", ["actor_id"])


def downgrade():
    op.drop_index("idx_blg_violations_actor", table_name="business_logic_violations")
    op.drop_index("idx_blg_violations_account", table_name="business_logic_violations")
    op.drop_table("business_logic_violations")

    op.drop_index("idx_blg_account", table_name="business_logic_graphs")
    op.drop_table("business_logic_graphs")
