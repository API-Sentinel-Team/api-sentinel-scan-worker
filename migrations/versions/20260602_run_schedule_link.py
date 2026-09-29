"""Link scheduled scan runs to their source schedule.

Revision ID: 20260602_run_schedule_link
Revises: 20260602_sched_pentest_profile
Create Date: 2026-06-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260602_run_schedule_link"
down_revision = "20260602_sched_pentest_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("source_schedule_id", sa.String(36), nullable=True))
    op.create_index(
        "ix_test_runs_source_schedule_id",
        "test_runs",
        ["source_schedule_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_test_runs_source_schedule_id", table_name="test_runs")
    op.drop_column("test_runs", "source_schedule_id")
