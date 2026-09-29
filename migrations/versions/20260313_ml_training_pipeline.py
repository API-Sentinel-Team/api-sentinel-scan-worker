"""
Add ML model artifacts and evaluation metrics tables.

Revision ID: 20260313_ml_training_pipeline
Revises: 20260313_enable_rls_policies
Create Date: 2026-03-13 00:00:11.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_ml_training_pipeline"
down_revision = "20260313_enable_rls_policies"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ml_models", sa.Column("artifact_path", sa.String(), nullable=True))
    op.add_column("ml_models", sa.Column("feature_keys", sa.JSON(), nullable=True))

    op.create_table(
        "ml_model_evaluations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ml_eval_account", "ml_model_evaluations", ["account_id"])
    op.create_index("idx_ml_eval_model", "ml_model_evaluations", ["model_id"])


def downgrade():
    op.drop_index("idx_ml_eval_model", table_name="ml_model_evaluations")
    op.drop_index("idx_ml_eval_account", table_name="ml_model_evaluations")
    op.drop_table("ml_model_evaluations")
    op.drop_column("ml_models", "feature_keys")
    op.drop_column("ml_models", "artifact_path")
