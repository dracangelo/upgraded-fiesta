# PostgreSQL backup, recovery, and retention operations

This runbook documents and validates PostgreSQL-native backup, restore, point-in-time
recovery, retention, schema rollback, and disaster recovery procedures. Run recovery
exercises only from an authorized operator workstation with `pg_dump`, `pg_restore`,
and `psql` installed.

## Preconditions

- Create an empty, access-controlled target database whose DSN/database name
  includes `recovery`.
- Export `ENUMSCAN_POSTGRES_DSN` for the primary source database and
  `ENUMSCAN_POSTGRES_RECOVERY_DSN` for the isolated recovery target.
- Ensure accounts follow least privilege: backup role needs `SELECT` on all enumscan
  tables and sequences; recovery role needs full DDL/DML on the recovery database only.
- Record the written authorization reference and release version outside this
  repository. Never place either DSN in shell history, a config file, or logs.

## Recovery drill exercise

```sh
export ENUMSCAN_RECOVERY_CONFIRM=RESTORE_ENUMSCAN_RECOVERY
make postgres-recovery-drill
```

The automated drill:
1. Validates that source and recovery target DSNs are distinct.
2. Validates that the recovery DSN explicitly contains `recovery` in its database name.
3. Validates that explicit operator confirmation `ENUMSCAN_RECOVERY_CONFIRM=RESTORE_ENUMSCAN_RECOVERY` is set.
4. Generates a mode-`0700` temporary custom-format dump (`pg_dump --format=custom`).
5. Restores into the recovery database (`pg_restore --clean --if-exists`).
6. Verifies migration ledger integrity (`SELECT COUNT(*) FROM postgres_schema_migrations`).
7. Removes temporary dump files upon completion or interrupt.

## Point-in-time recovery (PITR)

When continuous archiving is enabled in PostgreSQL:
1. Enable `wal_level = replica`, `archive_mode = on`, and `archive_command` to an access-controlled S3 or cold-storage bucket.
2. Schedule daily base backups via `pg_basebackup -Ft -z -D <backup_dir>`.
3. To recover to a specific timestamp before an incident:
   - Restore the base backup to an isolated node.
   - Configure `recovery_target_time = 'YYYY-MM-DD HH:MM:SS UTC'`.
   - Start the database in recovery mode; inspect `scan_runs` and `events` tables.
   - Once validated, promote the standby node.

## Schema migration and rollback

Enumscan manages PostgreSQL migrations through `postgres_schema_migrations`.
- To inspect current migrations:
  ```sh
  psql "$ENUMSCAN_POSTGRES_DSN" -c "SELECT version, applied_at FROM postgres_schema_migrations ORDER BY version;"
  ```
- Before schema changes, take a transactional snapshot or custom-format backup.
- In case of a failed migration or operational incompatibility, restore from the snapshot or revert schema changes using explicit down-scripts tested against the recovery target before touching production.

## Data retention, legal hold, and purge

1. **Retention bounds**: Purge completed scans older than the configured retention window (e.g. 90 days) using scoped transaction deletion:
   ```sql
   DELETE FROM scan_runs WHERE finished_at < NOW() - INTERVAL '90 days' AND status = 'completed';
   ```
2. **Legal hold**: Scans flagged with an active legal hold flag must be excluded from automated purge queries.
3. **Audit record**: Every purge operation logs the operator identity, timestamp, authorization reference, and affected scan IDs to `api_audit_log`.

## Post-recovery credential and key rotation

Immediately after completing a disaster-recovery or database-restore operation:
1. Rotate database connection credentials (`ENUMSCAN_POSTGRES_DSN`).
2. Rotate operator and API authentication tokens.
3. Verify that the envelope encryption key (`ENUMSCAN_ENCRYPTION_KEY`) can decrypt restored sensitive fields without errors.
4. Confirm health status via `GET /api/v1/health` and verify coordinator fencing via `DistributedCoordinatorStatus`.
