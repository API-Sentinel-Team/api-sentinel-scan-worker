"""
Add analytics aggregates and evidence details.

Revision ID: 20260313_analytics_and_evidence_details
Revises: 20260313_response_playbooks_and_retention
Create Date: 2026-03-13 00:00:03.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_analytics_and_evidence_details"
down_revision = "20260313_response_playbooks_and_retention"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("evidence_records", sa.Column("details", sa.JSON(), nullable=True))

    op.create_table(
        "endpoint_metrics_hourly",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("hour_ts", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("p95_latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_endpoint_metrics_account", "endpoint_metrics_hourly", ["account_id"])
    op.create_index("idx_endpoint_metrics_endpoint", "endpoint_metrics_hourly", ["endpoint_id"])
    op.create_index("idx_endpoint_metrics_hour", "endpoint_metrics_hourly", ["hour_ts"])

    op.create_table(
        "actor_metrics_hourly",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("hour_ts", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_latency_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_actor_metrics_account", "actor_metrics_hourly", ["account_id"])
    op.create_index("idx_actor_metrics_actor", "actor_metrics_hourly", ["actor_id"])
    op.create_index("idx_actor_metrics_hour", "actor_metrics_hourly", ["hour_ts"])

    op.create_table(
        "alert_metrics_daily",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("day", sa.String(10), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_alert_metrics_account", "alert_metrics_daily", ["account_id"])
    op.create_index("idx_alert_metrics_day", "alert_metrics_daily", ["day"])


def downgrade():
    op.drop_index("idx_alert_metrics_day", table_name="alert_metrics_daily")
    op.drop_index("idx_alert_metrics_account", table_name="alert_metrics_daily")
    op.drop_table("alert_metrics_daily")

    op.drop_index("idx_actor_metrics_hour", table_name="actor_metrics_hourly")
    op.drop_index("idx_actor_metrics_actor", table_name="actor_metrics_hourly")
    op.drop_index("idx_actor_metrics_account", table_name="actor_metrics_hourly")
    op.drop_table("actor_metrics_hourly")

    op.drop_index("idx_endpoint_metrics_hour", table_name="endpoint_metrics_hourly")
    op.drop_index("idx_endpoint_metrics_endpoint", table_name="endpoint_metrics_hourly")
    op.drop_index("idx_endpoint_metrics_account", table_name="endpoint_metrics_hourly")
    op.drop_table("endpoint_metrics_hourly")

    op.drop_column("evidence_records", "details")
