"""Widen sensor key column for prefixed HMAC storage.

Revision ID: 20260602_sensor_key_hash_storage
Revises: 20260601_test_run_worker_lease
Create Date: 2026-06-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260602_sensor_key_hash_storage"
down_revision = "20260601_test_run_worker_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sensors") as batch_op:
        batch_op.alter_column(
            "sensor_key",
            existing_type=sa.String(length=64),
            type_=sa.String(length=96),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("sensors") as batch_op:
        batch_op.alter_column(
            "sensor_key",
            existing_type=sa.String(length=96),
            type_=sa.String(length=64),
            existing_nullable=False,
        )
