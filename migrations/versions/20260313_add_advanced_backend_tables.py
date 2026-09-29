"""
Add advanced backend tables (revisions, specs, policy, evidence, DLQ).

Revision ID: 20260313_add_advanced_backend_tables
Revises: 20260313_add_ingestion_jobs_and_perf_indexes
Create Date: 2026-03-13 00:00:01.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_add_advanced_backend_tables"
down_revision = "20260313_add_ingestion_jobs_and_perf_indexes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ingestion_dead_letters",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=True),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ingest_dlq_account", "ingestion_dead_letters", ["account_id"])
    op.create_index("idx_ingest_dlq_job", "ingestion_dead_letters", ["job_id"])

    op.create_table(
        "endpoint_revisions",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=False),
        sa.Column("version_hash", sa.String(64), nullable=False),
        sa.Column("schema_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_endpoint_revisions_account", "endpoint_revisions", ["account_id"])
    op.create_index("idx_endpoint_revisions_endpoint", "endpoint_revisions", ["endpoint_id"])
    op.create_index("idx_endpoint_revisions_hash", "endpoint_revisions", ["version_hash"])

    op.create_table(
        "openapi_specs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.String(50), nullable=False, server_default="1.0.0"),
        sa.Column("spec_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_openapi_specs_account", "openapi_specs", ["account_id"])

    op.create_table(
        "policy_violations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("rule_id", sa.String(36), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("rule_type", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN"),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_policy_violations_account", "policy_violations", ["account_id"])
    op.create_index("idx_policy_violations_endpoint", "policy_violations", ["endpoint_id"])
    op.create_index("idx_policy_violations_rule", "policy_violations", ["rule_id"])

    op.create_table(
        "sensitive_data_findings",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("entity_type", sa.String(50), nullable=True),
        sa.Column("sample_value", sa.Text(), nullable=True),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True, server_default="0.5"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_sensitive_findings_account", "sensitive_data_findings", ["account_id"])
    op.create_index("idx_sensitive_findings_endpoint", "sensitive_data_findings", ["endpoint_id"])
    op.create_index("idx_sensitive_findings_type", "sensitive_data_findings", ["entity_type"])

    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("evidence_type", sa.String(50), nullable=False),
        sa.Column("ref_id", sa.String(36), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_evidence_account", "evidence_records", ["account_id"])
    op.create_index("idx_evidence_endpoint", "evidence_records", ["endpoint_id"])
    op.create_index("idx_evidence_ref", "evidence_records", ["ref_id"])


def downgrade():
    op.drop_index("idx_evidence_ref", table_name="evidence_records")
    op.drop_index("idx_evidence_endpoint", table_name="evidence_records")
    op.drop_index("idx_evidence_account", table_name="evidence_records")
    op.drop_table("evidence_records")

    op.drop_index("idx_sensitive_findings_type", table_name="sensitive_data_findings")
    op.drop_index("idx_sensitive_findings_endpoint", table_name="sensitive_data_findings")
    op.drop_index("idx_sensitive_findings_account", table_name="sensitive_data_findings")
    op.drop_table("sensitive_data_findings")

    op.drop_index("idx_policy_violations_rule", table_name="policy_violations")
    op.drop_index("idx_policy_violations_endpoint", table_name="policy_violations")
    op.drop_index("idx_policy_violations_account", table_name="policy_violations")
    op.drop_table("policy_violations")

    op.drop_index("idx_openapi_specs_account", table_name="openapi_specs")
    op.drop_table("openapi_specs")

    op.drop_index("idx_endpoint_revisions_hash", table_name="endpoint_revisions")
    op.drop_index("idx_endpoint_revisions_endpoint", table_name="endpoint_revisions")
    op.drop_index("idx_endpoint_revisions_account", table_name="endpoint_revisions")
    op.drop_table("endpoint_revisions")

    op.drop_index("idx_ingest_dlq_job", table_name="ingestion_dead_letters")
    op.drop_index("idx_ingest_dlq_account", table_name="ingestion_dead_letters")
    op.drop_table("ingestion_dead_letters")
