"""
Add lifecycle status to API endpoints.

Revision ID: 20260313_endpoint_lifecycle_status
Revises: 20260313_external_recon_findings
Create Date: 2026-03-13 00:00:08.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_endpoint_lifecycle_status"
down_revision = "20260313_external_recon_findings"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "api_endpoints",
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
    )
    op.create_index("idx_apiendpoint_status", "api_endpoints", ["status"])


def downgrade():
    op.drop_index("idx_apiendpoint_status", table_name="api_endpoints")
    op.drop_column("api_endpoints", "status")
