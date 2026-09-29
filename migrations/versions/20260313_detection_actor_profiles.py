"""
Add actor profile table for behavioral detection.

Revision ID: 20260313_detection_actor_profiles
Revises: 20260313_add_advanced_backend_tables
Create Date: 2026-03-13 00:00:02.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "20260313_detection_actor_profiles"
down_revision = "20260313_add_advanced_backend_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "actor_profiles",
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=False),
        sa.Column("endpoint_id", sa.String(36), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("recent_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("avg_response_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("actor_id", "account_id"),
    )
    op.create_index("idx_actor_profiles_account", "actor_profiles", ["account_id"])


def downgrade():
    op.drop_index("idx_actor_profiles_account", table_name="actor_profiles")
    op.drop_table("actor_profiles")
