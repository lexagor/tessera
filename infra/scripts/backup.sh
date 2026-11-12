#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
EVIDENCE_DIR="${EVIDENCE_DIR:-./data/evidence}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$BACKUP_DIR"
pg_dump "$DATABASE_URL" --format=custom --no-owner --file="$BACKUP_DIR/postgres-$STAMP.dump"

if [ -d "$EVIDENCE_DIR" ]; then
  tar -czf "$BACKUP_DIR/evidence-$STAMP.tar.gz" -C "$(dirname "$EVIDENCE_DIR")" "$(basename "$EVIDENCE_DIR")"
fi

find "$BACKUP_DIR" -type f \( -name 'postgres-*.dump' -o -name 'evidence-*.tar.gz' \) \
  -mtime +"$RETENTION_DAYS" -delete

echo "backup complete: $BACKUP_DIR ($STAMP)"
