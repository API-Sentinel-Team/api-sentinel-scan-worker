"""
Core engine enhancements: baselines and evidence packages.

Revision ID: 20260314_core_engine_improvements
Revises: 20260313_analytics_and_evidence_details
Create Date: 2026-03-14 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260314_core_engine_improvements"
down_revision = "20260313_analytics_and_evidence_details"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "actor_baselines",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("endpoint_history", sa.JSON(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_actor_baselines_account", "actor_baselines", ["account_id"])
    op.create_index("idx_actor_baselines_actor", "actor_baselines", ["actor_id"])

    op.create_table(
        "evidence_packages",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("detection_type", sa.String(50), nullable=False),
        sa.Column("detection_id", sa.String(36), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_evidence_packages_account", "evidence_packages", ["account_id"])
    op.create_index("idx_evidence_packages_detection", "evidence_packages", ["detection_type", "detection_id"])


def downgrade():
    op.drop_index("idx_evidence_packages_detection", table_name="evidence_packages")
    op.drop_index("idx_evidence_packages_account", table_name="evidence_packages")
    op.drop_table("evidence_packages")

    op.drop_index("idx_actor_baselines_actor", table_name="actor_baselines")
    op.drop_index("idx_actor_baselines_account", table_name="actor_baselines")
    op.drop_table("actor_baselines")
