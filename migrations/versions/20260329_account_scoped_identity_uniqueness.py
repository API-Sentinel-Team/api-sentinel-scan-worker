"""
Make threat/session/block identifiers account-scoped.

Revision ID: 20260329_acct_scoped_identity_uq
Revises: 20260313_ml_training_pipeline, 20260314_core_engine_improvements
Create Date: 2026-03-29 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260329_acct_scoped_identity_uq"
down_revision = ("20260313_ml_training_pipeline", "20260314_core_engine_improvements")
branch_labels = None
depends_on = None

_BATCH_NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def _find_unique_constraint_name(inspector, table_name: str, columns: list[str]) -> str | None:
    target = list(columns)
    for constraint in inspector.get_unique_constraints(table_name):
        if list(constraint.get("column_names") or []) == target:
            return constraint.get("name")
    return None


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return any(index.get("name") == index_name for index in inspector.get_indexes(table_name))


def _upgrade_sqlite() -> None:
    with op.batch_alter_table(
        "threat_actors",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_constraint("uq_threat_actors_source_ip", type_="unique")
        batch_op.create_unique_constraint(
            "uq_threat_actors_account_source_ip",
            ["account_id", "source_ip"],
        )

    with op.batch_alter_table(
        "agentic_sessions",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_constraint("uq_agentic_sessions_session_identifier", type_="unique")
        batch_op.create_unique_constraint(
            "uq_agentic_sessions_account_session_identifier",
            ["account_id", "session_identifier"],
        )
        batch_op.create_index("ix_agentic_sessions_account_id", ["account_id"], unique=False)

    with op.batch_alter_table(
        "blocked_ips",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_index("ix_blocked_ips_ip")
        batch_op.create_index("ix_blocked_ips_ip", ["ip"], unique=False)
        batch_op.create_unique_constraint(
            "uq_blocked_ips_account_ip",
            ["account_id", "ip"],
        )


def _downgrade_sqlite() -> None:
    with op.batch_alter_table(
        "blocked_ips",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_constraint("uq_blocked_ips_account_ip", type_="unique")
        batch_op.drop_index("ix_blocked_ips_ip")
        batch_op.create_index("ix_blocked_ips_ip", ["ip"], unique=True)

    with op.batch_alter_table(
        "agentic_sessions",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_constraint("uq_agentic_sessions_account_session_identifier", type_="unique")
        batch_op.drop_index("ix_agentic_sessions_account_id")
        batch_op.create_unique_constraint("uq_agentic_sessions_session_identifier", ["session_identifier"])

    with op.batch_alter_table(
        "threat_actors",
        recreate="always",
        naming_convention=_BATCH_NAMING,
    ) as batch_op:
        batch_op.drop_constraint("uq_threat_actors_account_source_ip", type_="unique")
        batch_op.create_unique_constraint("uq_threat_actors_source_ip", ["source_ip"])


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if bind.dialect.name == "sqlite":
        _upgrade_sqlite()
        return

    old_threat_actor_unique = _find_unique_constraint_name(inspector, "threat_actors", ["source_ip"])
    if old_threat_actor_unique:
        op.drop_constraint(old_threat_actor_unique, "threat_actors", type_="unique")
    op.create_unique_constraint(
        "uq_threat_actors_account_source_ip",
        "threat_actors",
        ["account_id", "source_ip"],
    )

    old_agentic_unique = _find_unique_constraint_name(inspector, "agentic_sessions", ["session_identifier"])
    if old_agentic_unique:
        op.drop_constraint(old_agentic_unique, "agentic_sessions", type_="unique")
    op.create_unique_constraint(
        "uq_agentic_sessions_account_session_identifier",
        "agentic_sessions",
        ["account_id", "session_identifier"],
    )
    if not _has_index(inspector, "agentic_sessions", "ix_agentic_sessions_account_id"):
        op.create_index("ix_agentic_sessions_account_id", "agentic_sessions", ["account_id"], unique=False)

    if _has_index(inspector, "blocked_ips", "ix_blocked_ips_ip"):
        op.drop_index("ix_blocked_ips_ip", table_name="blocked_ips")
    op.create_index("ix_blocked_ips_ip", "blocked_ips", ["ip"], unique=False)
    op.create_unique_constraint(
        "uq_blocked_ips_account_ip",
        "blocked_ips",
        ["account_id", "ip"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if bind.dialect.name == "sqlite":
        _downgrade_sqlite()
        return

    op.drop_constraint("uq_blocked_ips_account_ip", "blocked_ips", type_="unique")
    if _has_index(inspector, "blocked_ips", "ix_blocked_ips_ip"):
        op.drop_index("ix_blocked_ips_ip", table_name="blocked_ips")
    op.create_index("ix_blocked_ips_ip", "blocked_ips", ["ip"], unique=True)

    op.drop_constraint(
        "uq_agentic_sessions_account_session_identifier",
        "agentic_sessions",
        type_="unique",
    )
    if _has_index(inspector, "agentic_sessions", "ix_agentic_sessions_account_id"):
        op.drop_index("ix_agentic_sessions_account_id", table_name="agentic_sessions")
    op.create_unique_constraint(
        "uq_agentic_sessions_session_identifier",
        "agentic_sessions",
        ["session_identifier"],
    )

    op.drop_constraint("uq_threat_actors_account_source_ip", "threat_actors", type_="unique")
    op.create_unique_constraint("uq_threat_actors_source_ip", "threat_actors", ["source_ip"])
