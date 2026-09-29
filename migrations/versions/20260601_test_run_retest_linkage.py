"""Track vulnerability retest scan linkage.

Revision ID: 20260601_test_run_retest_linkage
Revises: 20260531_test_run_pentest_profile
Create Date: 2026-06-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260601_test_run_retest_linkage"
down_revision = "20260531_test_run_pentest_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("trigger_source", sa.String(50), nullable=True))
    op.add_column("test_runs", sa.Column("source_vulnerability_id", sa.String(36), nullable=True))
    op.create_index("ix_test_runs_trigger_source", "test_runs", ["trigger_source"], unique=False)
    op.create_index(
        "ix_test_runs_source_vulnerability_id",
        "test_runs",
        ["source_vulnerability_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_test_runs_source_vulnerability_id", table_name="test_runs")
    op.drop_index("ix_test_runs_trigger_source", table_name="test_runs")
    op.drop_column("test_runs", "source_vulnerability_id")
    op.drop_column("test_runs", "trigger_source")
