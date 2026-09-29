"""Track worker ownership and scan dispatch leases.

Revision ID: 20260601_test_run_worker_lease
Revises: 20260601_test_run_retest_linkage
Create Date: 2026-06-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260601_test_run_worker_lease"
down_revision = "20260601_test_run_retest_linkage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("test_runs", sa.Column("worker_id", sa.String(100), nullable=True))
    op.add_column("test_runs", sa.Column("dispatch_lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("test_runs", sa.Column("worker_heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("test_runs", sa.Column("claim_count", sa.Integer(), server_default="0", nullable=False))
    op.create_index("ix_test_runs_worker_id", "test_runs", ["worker_id"], unique=False)
    op.create_index(
        "ix_test_runs_dispatch_lease_expires_at",
        "test_runs",
        ["dispatch_lease_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_test_runs_dispatch_lease_expires_at", table_name="test_runs")
    op.drop_index("ix_test_runs_worker_id", table_name="test_runs")
    op.drop_column("test_runs", "claim_count")
    op.drop_column("test_runs", "worker_heartbeat_at")
    op.drop_column("test_runs", "dispatch_lease_expires_at")
    op.drop_column("test_runs", "worker_id")
