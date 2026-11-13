#!/bin/sh
set -eu
umask 077

# Weekly encrypted-backup restore drill for cron.
# Restores into a disposable database, verifies RLS, and records success for host-health.sh.

ENV_FILE="${ENV_FILE:-/opt/tessera/infra/docker/.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
PASSFILE="${BACKUP_PASSPHRASE_FILE:-/root/.tessera-backup-passphrase}"
STATE_FILE="${BACKUP_VERIFY_STAMP:-/var/lib/tessera-backup-verify/last_success}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-docker-postgres-1}"
SCRIPT_DIR="${TESSERA_SCRIPTS_DIR:-/opt/tessera/infra/scripts}"

[ -r "$ENV_FILE" ] || { echo "missing $ENV_FILE" >&2; exit 2; }
[ -r "$PASSFILE" ] || { echo "missing $PASSFILE" >&2; exit 2; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"

latest="$(ls -1t "$BACKUP_DIR"/tessera-backup-*.tar.gz.enc 2>/dev/null | head -1 || true)"
[ -n "$latest" ] || { echo "no encrypted backups in $BACKUP_DIR" >&2; exit 1; }

BACKUP_FILE="$latest" \
BACKUP_ENCRYPTION_PASSPHRASE="$(cat "$PASSFILE")" \
POSTGRES_CONTAINER="$POSTGRES_CONTAINER" \
POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  sh "$SCRIPT_DIR/verify-encrypted-backup.sh"

mkdir -p "$(dirname "$STATE_FILE")"
chmod 700 "$(dirname "$STATE_FILE")"
tmp="$STATE_FILE.tmp.$$"
date -u +%s > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$STATE_FILE"
echo "backup restore verification recorded: $STATE_FILE"
