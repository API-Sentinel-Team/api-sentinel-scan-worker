"""
PostgreSQL Row-Level Security (RLS) enforcement for multi-tenant isolation.

Enforces account_id-based access control at the database level.
This module provides SQL statements for enabling RLS on all multi-tenant tables.

IMPORTANT: RLS is only available in PostgreSQL. SQLite does not support RLS.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

# SQL statements for enabling RLS on each multi-tenant table
RLS_SETUP_STATEMENTS = {
    "api_endpoints": [
        # Enable RLS on the table
        "ALTER TABLE api_endpoints ENABLE ROW LEVEL SECURITY;",
        # Policy: Users can only see endpoints in their account
        """
        CREATE POLICY api_endpoints_account_isolation ON api_endpoints
        FOR SELECT
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
        # Policy: Users can only insert endpoints for their account
        """
        CREATE POLICY api_endpoints_insert_isolation ON api_endpoints
        FOR INSERT
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        # Policy: Users can only update endpoints in their account
        """
        CREATE POLICY api_endpoints_update_isolation ON api_endpoints
        FOR UPDATE
        USING (account_id = current_setting('app.current_account_id')::bigint)
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        # Policy: Users can only delete endpoints in their account
        """
        CREATE POLICY api_endpoints_delete_isolation ON api_endpoints
        FOR DELETE
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
    ],
    "vulnerabilities": [
        "ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;",
        """
        CREATE POLICY vulnerabilities_account_isolation ON vulnerabilities
        FOR SELECT
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY vulnerabilities_insert_isolation ON vulnerabilities
        FOR INSERT
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY vulnerabilities_update_isolation ON vulnerabilities
        FOR UPDATE
        USING (account_id = current_setting('app.current_account_id')::bigint)
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY vulnerabilities_delete_isolation ON vulnerabilities
        FOR DELETE
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
    ],
    "test_runs": [
        "ALTER TABLE test_runs ENABLE ROW LEVEL SECURITY;",
        """
        CREATE POLICY test_runs_account_isolation ON test_runs
        FOR SELECT
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_runs_insert_isolation ON test_runs
        FOR INSERT
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_runs_update_isolation ON test_runs
        FOR UPDATE
        USING (account_id = current_setting('app.current_account_id')::bigint)
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_runs_delete_isolation ON test_runs
        FOR DELETE
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
    ],
    "test_accounts": [
        "ALTER TABLE test_accounts ENABLE ROW LEVEL SECURITY;",
        """
        CREATE POLICY test_accounts_account_isolation ON test_accounts
        FOR SELECT
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_accounts_insert_isolation ON test_accounts
        FOR INSERT
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_accounts_update_isolation ON test_accounts
        FOR UPDATE
        USING (account_id = current_setting('app.current_account_id')::bigint)
        WITH CHECK (account_id = current_setting('app.current_account_id')::bigint);
        """,
        """
        CREATE POLICY test_accounts_delete_isolation ON test_accounts
        FOR DELETE
        USING (account_id = current_setting('app.current_account_id')::bigint);
        """,
    ],
}


async def enable_rls_on_all_tables(db: AsyncSession) -> dict:
    """
    Enable Row-Level Security on all multi-tenant tables.
    Sets up policies that enforce account_id-based isolation.

    Returns: dict with success/failure status for each table
    """
    results = {}

    for table_name, statements in RLS_SETUP_STATEMENTS.items():
        try:
            for statement in statements:
                if statement.strip():
                    await db.execute(text(statement))
            await db.commit()
            results[table_name] = {"status": "success", "message": "RLS enabled"}
            logger.info(f"rls_enabled_table: {table_name}")
        except Exception as e:
            results[table_name] = {"status": "error", "message": str(e)}
            logger.error(f"rls_setup_failed_table: {table_name}, error: {str(e)}")
            await db.rollback()

    return results


async def set_current_account_id(db: AsyncSession, account_id: int) -> None:
    """
    Set the current account_id in the PostgreSQL session.
    This is used by RLS policies to filter rows.

    Must be called before querying to enforce RLS filtering.
    """
    try:
        await db.execute(
            text(f"SET app.current_account_id = {account_id}")
        )
    except Exception as e:
        logger.warning(f"Failed to set current_account_id: {e}")


async def disable_rls_on_all_tables(db: AsyncSession) -> dict:
    """Disable RLS on all tables (use for testing or migration)."""
    results = {}
    tables = ["api_endpoints", "vulnerabilities", "test_runs", "test_accounts"]

    for table_name in tables:
        try:
            await db.execute(text(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;"))
            # Drop all policies for this table
            policies = [
                f"{table_name}_account_isolation",
                f"{table_name}_insert_isolation",
                f"{table_name}_update_isolation",
                f"{table_name}_delete_isolation",
            ]
            for policy in policies:
                try:
                    await db.execute(text(f"DROP POLICY IF EXISTS {policy} ON {table_name};"))
                except:
                    pass

            await db.commit()
            results[table_name] = {"status": "success"}
        except Exception as e:
            results[table_name] = {"status": "error", "message": str(e)}
            logger.error(f"rls_disable_failed: {table_name}, error: {str(e)}")
            await db.rollback()

    return results
