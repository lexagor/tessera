#!/bin/sh
set -eu

# Non-destructive encrypted-backup restore drill.
# Restores the Postgres dump into a disposable database and verifies the evidence archive.
#
#   BACKUP_FILE=/var/backups/tessera/tessera-backup-....tar.gz.enc \
#   BACKUP_ENCRYPTION_PASSPHRASE=... \
#   POSTGRES_CONTAINER=docker-postgres-1 POSTGRES_PASSWORD=... \
#   infra/scripts/verify-encrypted-backup.sh

: "${BACKUP_FILE:?BACKUP_FILE is required}"
: "${BACKUP_ENCRYPTION_PASSPHRASE:?BACKUP_ENCRYPTION_PASSPHRASE is required}"
: "${POSTGRES_CONTAINER:?POSTGRES_CONTAINER is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
command -v openssl >/dev/null 2>&1 || { echo "openssl required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker required" >&2; exit 2; }

TMP="$(mktemp -d)"
DB="tessera_restore_test_$(date -u +%Y%m%d%H%M%S)"
KEEP=0
cleanup() {
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
    psql -U "${POSTGRES_USER:-tessera}" -d postgres -c "DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1 || true
  docker exec "$POSTGRES_CONTAINER" rm -f /tmp/tessera-restore.dump >/dev/null 2>&1 || true
  [ "$KEEP" = "1" ] || rm -rf "$TMP"
}
trap cleanup EXIT

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -pass env:BACKUP_ENCRYPTION_PASSPHRASE -in "$BACKUP_FILE" -out "$TMP/bundle.tar.gz"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP"
DUMP="$(find "$TMP" -maxdepth 1 -name 'postgres-*.dump' | head -1)"
EVIDENCE="$(find "$TMP" -maxdepth 1 -name 'evidence-*.tar.gz' | head -1)"
[ -n "$DUMP" ] || { echo "no postgres dump in bundle" >&2; exit 1; }
[ -n "$EVIDENCE" ] || { echo "no evidence archive in bundle" >&2; exit 1; }
tar -tzf "$EVIDENCE" >/dev/null

docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "${POSTGRES_USER:-tessera}" -d postgres -c "CREATE DATABASE $DB" >/dev/null
docker cp "$DUMP" "$POSTGRES_CONTAINER:/tmp/tessera-restore.dump" >/dev/null
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  pg_restore -U "${POSTGRES_USER:-tessera}" -d "$DB" --no-owner /tmp/tessera-restore.dump >/dev/null

migrations="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "${POSTGRES_USER:-tessera}" -d "$DB" -tAc 'SELECT count(*) FROM schema_migrations')"
users="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "${POSTGRES_USER:-tessera}" -d "$DB" -tAc 'SELECT count(*) FROM users')"
rls="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "${POSTGRES_USER:-tessera}" -d "$DB" -tAc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relrowsecurity AND c.relforcerowsecurity AND c.relname IN ('orgs','actions','memberships','sessions','environments','evidence_packs','scim_tokens')")"

echo "encrypted backup restore ok"
echo "  migrations: ${migrations:-0}"
echo "  users: ${users:-0}"
echo "  forced RLS tables sampled: ${rls:-0}/7"
[ "${migrations:-0}" -ge 1 ] || { echo "restored database has no migrations" >&2; exit 1; }
[ "${rls:-0}" -ge 7 ] || { echo "restored database is missing control-plane RLS" >&2; exit 1; }
