"""
Add ML model registry and feature store tables.

Revision ID: 20260313_ml_tables
Revises: 20260313_enforcement_tables
Create Date: 2026-03-13 00:00:05.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_ml_tables"
down_revision = "20260313_enforcement_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ml_models",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50), nullable=False, server_default="1.0.0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="SHADOW"),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ml_models_account", "ml_models", ["account_id"])
    op.create_index("idx_ml_models_name", "ml_models", ["name"])

    op.create_table(
        "ml_model_runs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("features", sa.JSON(), nullable=True),
        sa.Column("is_alert", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ml_runs_account", "ml_model_runs", ["account_id"])
    op.create_index("idx_ml_runs_model", "ml_model_runs", ["model_id"])

    op.create_table(
        "feature_vectors",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("window_start", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("features", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_feature_vectors_account", "feature_vectors", ["account_id"])
    op.create_index("idx_feature_vectors_actor", "feature_vectors", ["actor_id"])
    op.create_index("idx_feature_vectors_endpoint", "feature_vectors", ["endpoint_id"])
    op.create_index("idx_feature_vectors_window", "feature_vectors", ["window_start"])


def downgrade():
    op.drop_index("idx_feature_vectors_window", table_name="feature_vectors")
    op.drop_index("idx_feature_vectors_endpoint", table_name="feature_vectors")
    op.drop_index("idx_feature_vectors_actor", table_name="feature_vectors")
    op.drop_index("idx_feature_vectors_account", table_name="feature_vectors")
    op.drop_table("feature_vectors")

    op.drop_index("idx_ml_runs_model", table_name="ml_model_runs")
    op.drop_index("idx_ml_runs_account", table_name="ml_model_runs")
    op.drop_table("ml_model_runs")

    op.drop_index("idx_ml_models_name", table_name="ml_models")
    op.drop_index("idx_ml_models_account", table_name="ml_models")
    op.drop_table("ml_models")
