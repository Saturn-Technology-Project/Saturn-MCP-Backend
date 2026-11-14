# Migrations

Schema changes are Alembic migrations in `alembic/versions/`. They run as a Cloud Run Job
before each deploy, while the previous revision of the API is still serving traffic.

## How a run works

- One runner at a time. `alembic/env.py` takes a PostgreSQL advisory lock for the whole run;
  a second runner waits up to `MIGRATION_LOCK_WAIT` (default `300s`), then finds nothing to do.
- Each migration is its own transaction. A failure rolls back that migration only; the ones
  before it stay applied and `alembic upgrade head` continues from there when run again.
- A DDL statement waits at most 60 seconds for a table lock (`lock_timeout`). If a live
  request holds the lock longer, the migration fails instead of queueing every other query
  behind it. Run it again.

## Rules

1. **The old code must keep working.** The previous API revision runs during and after the
   migration, and is what a rollback returns to. A migration never removes or renames
   something that revision reads or writes.
2. **Make it safe to run twice.** Check for the table, column or index first, as the existing
   migrations do, so a retried job does not fail on what the first attempt already created.
3. **Write a real `downgrade`.** CI reverses and reapplies the newest migration. A downgrade
   that cannot restore data says so in a comment (see `009_remove_demo_catalog`).

## Changing a large table: expand, then contract

A change that would rewrite or lock a large table (`audit_logs`, `webhook_deliveries`,
`actions`) is split over releases, so no single step blocks writes or breaks the running code.

| Step | Release | What ships |
|---|---|---|
| Expand | N | Add the new column, nullable and without a default that rewrites the table, or the new table or index. Code writes both the old and the new shape and still reads the old one. |
| Backfill | N | Fill old rows in batches from a command in `app/cli/`, not inside the migration. Each batch is its own short transaction. |
| Switch | N+1 | Code reads the new shape. Add `NOT NULL` or other constraints now: as `NOT VALID`, then `VALIDATE CONSTRAINT` in a second statement. |
| Contract | N+2 | Drop the old column or index, once no deployed revision uses it. |

Renaming a column is this same sequence with a new column, never `ALTER ... RENAME`.

## Indexes on a large table

A plain `CREATE INDEX` blocks writes to the table while it builds. Build it concurrently,
which has to happen outside a transaction:

```python
def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_logs_example "
            "ON audit_logs (organization_id, created_at)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_audit_logs_example")
```

Keep such an index in a migration of its own. Statements before `autocommit_block()` in the
same migration are committed when the block starts, so they no longer roll back with it.

A concurrent build that fails leaves an `INVALID` index behind. `IF NOT EXISTS` then skips
it, so drop it first: `DROP INDEX CONCURRENTLY IF EXISTS <name>`.

SQLite (the test suite) has no `CONCURRENTLY`. Tests build the schema from the models, not
from migrations, so they never run these statements; the `migrations` job in CI runs them on
PostgreSQL.
