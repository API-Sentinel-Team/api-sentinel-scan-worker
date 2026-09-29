from logging.config import fileConfig
import os
from pathlib import Path
import sys

from sqlalchemy import engine_from_config
from sqlalchemy import pool
import sqlalchemy as sa
from alembic import context
import asyncio
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic.script import ScriptDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

database_url = os.getenv("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
from server.models import Base
target_metadata = Base.metadata


def _command_name() -> str | None:
    cmd_opts = getattr(config, "cmd_opts", None)
    cmd = getattr(cmd_opts, "cmd", None)
    if isinstance(cmd, tuple) and cmd:
        return getattr(cmd[0], "__name__", None)
    return None


def _bootstrap_fresh_database(connection) -> None:
    """Allow `alembic upgrade head` to succeed on a truly empty database.

    The historical migration chain in this repo was generated against existing
    databases and the earliest baseline revision does not create the original
    core tables. For greenfield installs we bootstrap the current metadata once,
    stamp the head revision, and then let Alembic continue normally.
    """

    if _command_name() != "upgrade":
        return

    inspector = sa.inspect(connection)
    user_tables = [
        table_name
        for table_name in inspector.get_table_names()
        if table_name != "alembic_version" and not table_name.startswith("sqlite_")
    ]
    if user_tables:
        return

    target_metadata.create_all(connection)

    # Revision ids in this repo can exceed Alembic's historic 32-char default
    # (e.g. 20260715_test_account_identity_matrix).
    version_table = sa.Table(
        "alembic_version",
        sa.MetaData(),
        sa.Column("version_num", sa.String(128), nullable=False, primary_key=True),
    )
    version_table.create(connection, checkfirst=True)
    connection.execute(sa.delete(version_table))

    script = ScriptDirectory.from_config(config)
    for head in script.get_heads():
        connection.execute(version_table.insert().values(version_num=head))
    connection.commit()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def do_run_migrations(connection):
    _bootstrap_fresh_database(connection)
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()
    connection.commit()

async def run_async_migrations():
    """In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    import server.models  # load models
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
