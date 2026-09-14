#!/usr/bin/env sh
# Exercise PostgreSQL-native recovery only against an explicitly named,
# separate recovery database. This script intentionally never prints DSNs.
set -eu

source_dsn=${ENUMSCAN_POSTGRES_DSN:?set ENUMSCAN_POSTGRES_DSN}
target_dsn=${ENUMSCAN_POSTGRES_RECOVERY_DSN:?set ENUMSCAN_POSTGRES_RECOVERY_DSN}
[ "$source_dsn" != "$target_dsn" ] || { echo "source and recovery DSNs must differ" >&2; exit 2; }
case "$target_dsn" in
  *recovery*|*RECOVERY*) ;;
  *) echo "recovery target DSN must identify a database containing 'recovery'" >&2; exit 2 ;;
esac
[ "${ENUMSCAN_RECOVERY_CONFIRM:-}" = "RESTORE_ENUMSCAN_RECOVERY" ] || {
  echo "set ENUMSCAN_RECOVERY_CONFIRM=RESTORE_ENUMSCAN_RECOVERY to permit restore" >&2
  exit 2
}
for command in pg_dump pg_restore psql mktemp; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command unavailable: $command" >&2; exit 2; }
done

umask 077
recovery_dir=$(mktemp -d "${TMPDIR:-/tmp}/enumscan-postgres-recovery.XXXXXX")
dump_path="$recovery_dir/enumscan.dump"
cleanup() { rm -rf "$recovery_dir"; }
trap cleanup EXIT HUP INT TERM

pg_dump --format=custom --no-owner --no-privileges "$source_dsn" > "$dump_path"
pg_restore --clean --if-exists --no-owner --no-privileges --dbname="$target_dsn" "$dump_path"
migrations=$(psql "$target_dsn" -v ON_ERROR_STOP=1 -Atc 'SELECT COUNT(*) FROM postgres_schema_migrations')
case "$migrations" in
  ''|0|*[!0-9]*) echo "recovery target has no valid enumscan migration ledger" >&2; exit 1 ;;
esac
echo "PostgreSQL recovery drill passed (migration ledger entries: $migrations)."
