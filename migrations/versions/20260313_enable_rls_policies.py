"""
Enable row-level security policies for tenant isolation.

Revision ID: 20260313_enable_rls_policies
Revises: 20260313_recon_sources
Create Date: 2026-03-13 00:00:10.000000
"""
from alembic import op

revision = "20260313_enable_rls_policies"
down_revision = "20260313_recon_sources"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(
        """
        DO $$
        DECLARE r RECORD;
        BEGIN
            FOR r IN
                SELECT table_schema, table_name
                FROM information_schema.columns
                WHERE column_name = 'account_id'
                  AND table_schema = 'public'
            LOOP
                EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_policies
                    WHERE schemaname = r.table_schema
                      AND tablename = r.table_name
                      AND policyname = 'tenant_isolation'
                ) THEN
                    EXECUTE format(
                        'CREATE POLICY tenant_isolation ON %I.%I USING (account_id::text = current_setting(''app.current_account_id'', true))',
                        r.table_schema, r.table_name
                    );
                END IF;
            END LOOP;
        END $$;
        """
    )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(
        """
        DO $$
        DECLARE r RECORD;
        BEGIN
            FOR r IN
                SELECT table_schema, table_name
                FROM information_schema.columns
                WHERE column_name = 'account_id'
                  AND table_schema = 'public'
            LOOP
                EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', r.table_schema, r.table_name);
                EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);
            END LOOP;
        END $$;
        """
    )
