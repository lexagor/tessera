#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
EVIDENCE_DIR="${EVIDENCE_DIR:-./data/evidence}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
OFFSITE_DIR="${BACKUP_OFFSITE_DIR:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$BACKUP_DIR"
pg_dump "$DATABASE_URL" --format=custom --no-owner --file="$BACKUP_DIR/postgres-$STAMP.dump"

if [ -d "$EVIDENCE_DIR" ]; then
  tar -czf "$BACKUP_DIR/evidence-$STAMP.tar.gz" -C "$(dirname "$EVIDENCE_DIR")" "$(basename "$EVIDENCE_DIR")"
fi

if [ -n "$OFFSITE_DIR" ]; then
  mkdir -p "$OFFSITE_DIR"
  cp "$BACKUP_DIR/postgres-$STAMP.dump" "$OFFSITE_DIR/"
  if [ -f "$BACKUP_DIR/evidence-$STAMP.tar.gz" ]; then
    cp "$BACKUP_DIR/evidence-$STAMP.tar.gz" "$OFFSITE_DIR/"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OFFSITE_DIR" && sha256sum ./* > SHA256SUMS)
  else
    (cd "$OFFSITE_DIR" && shasum -a 256 ./* > SHA256SUMS)
  fi
fi

find "$BACKUP_DIR" -type f \( -name 'postgres-*.dump' -o -name 'evidence-*.tar.gz' \) \
  -mtime +"$RETENTION_DAYS" -delete

echo "backup complete: $BACKUP_DIR ($STAMP${OFFSITE_DIR:+; offsite: $OFFSITE_DIR})"
