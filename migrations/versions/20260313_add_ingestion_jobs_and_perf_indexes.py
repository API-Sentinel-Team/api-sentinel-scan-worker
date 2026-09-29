"""
Add ingestion_jobs table and performance indexes.

Revision ID: 20260313_add_ingestion_jobs_and_perf_indexes
Revises: add_indexes_and_jwt_revocation
Create Date: 2026-03-13 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260313_add_ingestion_jobs_and_perf_indexes"
down_revision = "add_indexes_and_jwt_revocation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("job_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="QUEUED"),
        sa.Column("accepted_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("processed_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("threats_detected", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ingestion_jobs_account", "ingestion_jobs", ["account_id"])
    op.create_index("idx_ingestion_jobs_status", "ingestion_jobs", ["status"])
    op.create_index("idx_ingestion_jobs_type", "ingestion_jobs", ["job_type"])

    op.create_index("idx_request_logs_account_created", "request_logs", ["account_id", "created_at"])
    op.create_index("idx_vulns_account_severity_created", "vulnerabilities", ["account_id", "severity", "created_at"])
    op.create_index("idx_endpoints_account_last_seen", "api_endpoints", ["account_id", "last_seen"])
    op.create_index("idx_malicious_account_detected", "malicious_event_records", ["account_id", "detected_at"])
    op.create_index("idx_malicious_account_severity", "malicious_event_records", ["account_id", "severity"])
    op.create_index("idx_waf_account_created", "waf_events", ["account_id", "created_at"])


def downgrade():
    op.drop_index("idx_waf_account_created", table_name="waf_events")
    op.drop_index("idx_malicious_account_severity", table_name="malicious_event_records")
    op.drop_index("idx_malicious_account_detected", table_name="malicious_event_records")
    op.drop_index("idx_endpoints_account_last_seen", table_name="api_endpoints")
    op.drop_index("idx_vulns_account_severity_created", table_name="vulnerabilities")
    op.drop_index("idx_request_logs_account_created", table_name="request_logs")

    op.drop_index("idx_ingestion_jobs_type", table_name="ingestion_jobs")
    op.drop_index("idx_ingestion_jobs_status", table_name="ingestion_jobs")
    op.drop_index("idx_ingestion_jobs_account", table_name="ingestion_jobs")
    op.drop_table("ingestion_jobs")
