#!/bin/sh
set -eu

# Fail if no recent database/evidence backup exists. Intended for cron/monitoring wrappers.
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
MAX_AGE_HOURS="${MAX_AGE_HOURS:-26}"
MAX_AGE_MIN=$((MAX_AGE_HOURS * 60))

latest_encrypted=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'tessera-backup-*.tar.gz.enc' -mmin -"$MAX_AGE_MIN" 2>/dev/null | sort | tail -1)
if [ -n "$latest_encrypted" ]; then
  latest_db="$latest_encrypted"
  latest_evidence="$latest_encrypted"
else
  latest_db=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'postgres-*.dump' -mmin -"$MAX_AGE_MIN" 2>/dev/null | sort | tail -1)
  latest_evidence=$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'evidence-*.tar.gz' -mmin -"$MAX_AGE_MIN" 2>/dev/null | sort | tail -1)
fi

if [ -z "$latest_db" ] || [ -z "$latest_evidence" ]; then
  echo "STALE: no postgres/evidence backup newer than ${MAX_AGE_HOURS}h in $BACKUP_DIR" >&2
  [ -n "$latest_db" ] && echo "latest db: $latest_db" >&2
  [ -n "$latest_evidence" ] && echo "latest evidence: $latest_evidence" >&2
  exit 1
fi

echo "fresh backups:"
echo "  db: $latest_db"
echo "  evidence: $latest_evidence"
