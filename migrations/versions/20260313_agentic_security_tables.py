"""
Add agentic identity and MCP telemetry tables.

Revision ID: 20260313_agentic_security_tables
Revises: 20260313_business_logic_graphs
Create Date: 2026-03-13 00:00:04.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "20260313_agentic_security_tables"
down_revision = "20260313_business_logic_graphs"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_identities",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("agent_type", sa.String(50), nullable=True),
        sa.Column("parent_agent_id", sa.String(255), nullable=True),
        sa.Column("declared_scope", sa.JSON(), nullable=True),
        sa.Column("effective_scope", sa.JSON(), nullable=True),
        sa.Column("human_principal", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_agent_identities_account", "agent_identities", ["account_id"])
    op.create_index("idx_agent_identities_agent", "agent_identities", ["agent_id"])

    op.create_table(
        "mcp_tool_invocations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("agent_id", sa.String(255), nullable=True),
        sa.Column("tool_name", sa.String(255), nullable=True),
        sa.Column("parameters", sa.JSON(), nullable=True),
        sa.Column("result_excerpt", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="OK"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_mcp_invocations_account", "mcp_tool_invocations", ["account_id"])
    op.create_index("idx_mcp_invocations_agent", "mcp_tool_invocations", ["agent_id"])

    op.create_table(
        "agentic_violations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=True),
        sa.Column("agent_id", sa.String(255), nullable=True),
        sa.Column("violation_type", sa.String(100), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="MEDIUM"),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_agentic_violations_account", "agentic_violations", ["account_id"])
    op.create_index("idx_agentic_violations_agent", "agentic_violations", ["agent_id"])


def downgrade():
    op.drop_index("idx_agentic_violations_agent", table_name="agentic_violations")
    op.drop_index("idx_agentic_violations_account", table_name="agentic_violations")
    op.drop_table("agentic_violations")

    op.drop_index("idx_mcp_invocations_agent", table_name="mcp_tool_invocations")
    op.drop_index("idx_mcp_invocations_account", table_name="mcp_tool_invocations")
    op.drop_table("mcp_tool_invocations")

    op.drop_index("idx_agent_identities_agent", table_name="agent_identities")
    op.drop_index("idx_agent_identities_account", table_name="agent_identities")
    op.drop_table("agent_identities")
