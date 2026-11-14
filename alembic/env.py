import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.core.config import get_settings
from app.db.database import Base
from app.models import *  # noqa: F401,F403

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# Any fixed 64-bit key works; it only has to be the same for every runner.
# int.from_bytes(hashlib.sha256(b"saturn-alembic-upgrade").digest()[:8], "big", signed=True)
_MIGRATION_LOCK_KEY = 3_886_794_715_833_081_572
# How long a second runner waits for the first to finish before giving up.
_MIGRATION_LOCK_WAIT = os.environ.get("MIGRATION_LOCK_WAIT", "300s")
# How long one DDL statement may wait on a table lock that a live request holds.
_DDL_LOCK_TIMEOUT = "60s"


def _serialise_postgres(connection: Connection) -> bool:
    """Take the migration lock for this connection. True when it was taken and must be released.

    Concurrent runners (a Cloud Run Job retry, or several containers that still
    migrate on start) queue on the advisory lock. The next one then reads the
    new alembic_version and has nothing to do. Live connections are never
    terminated: if a request holds a lock longer than the DDL lock timeout, the
    migration fails and can be retried, instead of breaking traffic.

    The lock and the timeouts belong to the session, not to one transaction, because each
    migration now commits on its own (see docs/migrations.md).
    """
    if connection.dialect.name != "postgresql":
        return False
    connection.execute(text("SELECT set_config('lock_timeout', :value, false)"), {"value": _MIGRATION_LOCK_WAIT})
    connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _MIGRATION_LOCK_KEY})
    connection.execute(text("SELECT set_config('lock_timeout', :value, false)"), {"value": _DDL_LOCK_TIMEOUT})
    # End the transaction these statements opened. Alembic only manages transactions itself
    # when it is handed a connection that is not already inside one.
    connection.commit()
    return True


def do_run_migrations(connection: Connection) -> None:
    locked = _serialise_postgres(connection)
    try:
        # One transaction per migration, not one around the whole run: a migration can then leave
        # its transaction (op.get_context().autocommit_block()) for CREATE INDEX CONCURRENTLY,
        # and a long run does not hold every lock it took until the last migration finishes.
        context.configure(connection=connection, target_metadata=target_metadata, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()
    finally:
        if locked:
            if connection.in_transaction():
                connection.rollback()
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": _MIGRATION_LOCK_KEY})
            connection.commit()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
