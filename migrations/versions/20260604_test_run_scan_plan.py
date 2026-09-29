"""Add durable active scan plans to test runs.

Revision ID: 20260604_test_run_scan_plan
Revises: 20260604_pentest_profile_destructive_arming
Create Date: 2026-06-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260604_test_run_scan_plan"
down_revision = "20260604_pentest_profile_destructive_arming"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(table_name)


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    return any(
        column["name"] == column_name
        for column in sa.inspect(bind).get_columns(table_name)
    )


def upgrade() -> None:
    if not _has_table("test_runs"):
        return

    with op.batch_alter_table("test_runs") as batch_op:
        if not _has_column("test_runs", "test_intensity"):
            batch_op.add_column(
                sa.Column(
                    "test_intensity",
                    sa.String(length=20),
                    nullable=False,
                    server_default="standard",
                )
            )
            batch_op.alter_column("test_intensity", server_default=None)
        if not _has_column("test_runs", "scan_plan"):
            batch_op.add_column(sa.Column("scan_plan", sa.JSON(), nullable=True))


def downgrade() -> None:
    if not _has_table("test_runs"):
        return

    with op.batch_alter_table("test_runs") as batch_op:
        if _has_column("test_runs", "scan_plan"):
            batch_op.drop_column("scan_plan")
        if _has_column("test_runs", "test_intensity"):
            batch_op.drop_column("test_intensity")
