"""Add identity-matrix columns to test_accounts.

Revision ID: 20260715_test_account_identity_matrix
Revises: 20260604_test_run_scan_plan
Create Date: 2026-07-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260715_test_account_identity_matrix"
down_revision = "20260604_test_run_scan_plan"
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
    if not _has_table("test_accounts"):
        return

    with op.batch_alter_table("test_accounts") as batch_op:
        if not _has_column("test_accounts", "status"):
            batch_op.add_column(
                sa.Column(
                    "status",
                    sa.String(length=20),
                    nullable=False,
                    server_default="ACTIVE",
                )
            )
            batch_op.alter_column("status", server_default=None)
        if not _has_column("test_accounts", "expired_at"):
            batch_op.add_column(
                sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True)
            )
        if not _has_column("test_accounts", "tenant_id"):
            batch_op.add_column(
                sa.Column("tenant_id", sa.String(length=36), nullable=True, index=True)
            )


def downgrade() -> None:
    if not _has_table("test_accounts"):
        return

    with op.batch_alter_table("test_accounts") as batch_op:
        if _has_column("test_accounts", "tenant_id"):
            batch_op.drop_column("tenant_id")
        if _has_column("test_accounts", "expired_at"):
            batch_op.drop_column("expired_at")
        if _has_column("test_accounts", "status"):
            batch_op.drop_column("status")
