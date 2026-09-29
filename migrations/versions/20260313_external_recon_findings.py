"""
Add external recon findings table.

Revision ID: 20260313_external_recon_findings
Revises: 20260313_warm_export_cursors
Create Date: 2026-03-13 00:00:07.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_external_recon_findings"
down_revision = "20260313_warm_export_cursors"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "external_recon_findings",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("method", sa.String(10), nullable=False, server_default="GET"),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("path_pattern", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("status", sa.String(20), nullable=False, server_default="NEW"),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "account_id",
            "source",
            "method",
            "host",
            "path_pattern",
            name="uq_recon_finding",
        ),
    )
    op.create_index("idx_recon_account", "external_recon_findings", ["account_id"])
    op.create_index("idx_recon_host", "external_recon_findings", ["host"])
    op.create_index("idx_recon_path_pattern", "external_recon_findings", ["path_pattern"])


def downgrade():
    op.drop_index("idx_recon_path_pattern", table_name="external_recon_findings")
    op.drop_index("idx_recon_host", table_name="external_recon_findings")
    op.drop_index("idx_recon_account", table_name="external_recon_findings")
    op.drop_table("external_recon_findings")
