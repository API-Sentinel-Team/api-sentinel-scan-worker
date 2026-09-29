"""
Add response playbooks and tenant retention policies.

Revision ID: 20260313_response_playbooks_and_retention
Revises: 20260313_agentic_security_tables
Create Date: 2026-03-13 00:00:02.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_response_playbooks_and_retention"
down_revision = "20260313_agentic_security_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tenant_retention_policies",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True, unique=True),
        sa.Column("full_payload_retention", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("retain_request_headers", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("retain_response_bodies", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("retention_encryption_key_id", sa.String(255), nullable=True),
        sa.Column("retention_period_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("pii_categories_to_retain", sa.JSON(), nullable=True),
        sa.Column("pii_vault_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_retention_account", "tenant_retention_policies", ["account_id"])

    op.create_table(
        "response_playbooks",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("trigger", sa.String(100), nullable=False, server_default="alert.created"),
        sa.Column("severity_threshold", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("actions", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_playbooks_account", "response_playbooks", ["account_id"])
    op.create_index("idx_playbooks_trigger", "response_playbooks", ["trigger"])

    op.create_table(
        "response_action_logs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("playbook_id", sa.String(36), nullable=True),
        sa.Column("alert_id", sa.String(36), nullable=True),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="SUCCESS"),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_action_logs_account", "response_action_logs", ["account_id"])
    op.create_index("idx_action_logs_alert", "response_action_logs", ["alert_id"])
    op.create_index("idx_action_logs_playbook", "response_action_logs", ["playbook_id"])


def downgrade():
    op.drop_index("idx_action_logs_playbook", table_name="response_action_logs")
    op.drop_index("idx_action_logs_alert", table_name="response_action_logs")
    op.drop_index("idx_action_logs_account", table_name="response_action_logs")
    op.drop_table("response_action_logs")

    op.drop_index("idx_playbooks_trigger", table_name="response_playbooks")
    op.drop_index("idx_playbooks_account", table_name="response_playbooks")
    op.drop_table("response_playbooks")

    op.drop_index("idx_retention_account", table_name="tenant_retention_policies")
    op.drop_table("tenant_retention_policies")
