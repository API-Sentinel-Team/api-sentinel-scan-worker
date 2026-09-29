"""Persist Host header on request_logs for live inventory grouping.

Revision ID: 20260815_request_log_host
Revises: 20260715_test_account_identity_matrix
Create Date: 2026-08-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260815_request_log_host"
down_revision = "20260715_test_account_identity_matrix"
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
    if not _has_table("request_logs"):
        return
    if _has_column("request_logs", "host"):
        return
    op.add_column("request_logs", sa.Column("host", sa.String(length=255), nullable=True))


def downgrade() -> None:
    if not _has_table("request_logs"):
        return
    if not _has_column("request_logs", "host"):
        return
    op.drop_column("request_logs", "host")
