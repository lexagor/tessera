#!/bin/sh
set -eu
umask 077

ENV_FILE="${ENV_FILE:-/opt/tessera/infra/docker/.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-docker-postgres-1}"
EVIDENCE_VOLUME="${EVIDENCE_VOLUME:-docker_evidence}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
OFFSITE_DIR="${BACKUP_OFFSITE_DIR:-}"
ENCRYPTION_PASSPHRASE="${BACKUP_ENCRYPTION_PASSPHRASE:-}"
ENCRYPTION_ONLY="${BACKUP_ENCRYPTION_ONLY:-1}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

: "${ENV_FILE:?ENV_FILE is required}"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"

if [ -n "$OFFSITE_DIR" ] && [ -z "$ENCRYPTION_PASSPHRASE" ]; then
  echo "refusing an unencrypted offsite copy; set BACKUP_ENCRYPTION_PASSPHRASE" >&2
  exit 2
fi
if [ -n "$ENCRYPTION_PASSPHRASE" ] && ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required for BACKUP_ENCRYPTION_PASSPHRASE" >&2
  exit 2
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  pg_dump -U tessera -Fc -d tessera -f "/tmp/postgres-$STAMP.dump"
docker cp "$POSTGRES_CONTAINER:/tmp/postgres-$STAMP.dump" "$BACKUP_DIR/postgres-$STAMP.dump"
docker exec "$POSTGRES_CONTAINER" rm -f "/tmp/postgres-$STAMP.dump"

if [ -n "${EVIDENCE_S3_BUCKET:-}" ]; then
  echo "WARN: EVIDENCE_S3_BUCKET is set; evidence is in object storage, not docker_evidence." >&2
  echo "WARN: back up/replicate the bucket separately; the local archive may be empty." >&2
fi

docker run --rm \
  -v "$EVIDENCE_VOLUME:/data:ro" \
  -v "$BACKUP_DIR:/backup" \
  postgres:16-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139 \
  tar -czf "/backup/evidence-$STAMP.tar.gz" -C /data .

if [ -n "$ENCRYPTION_PASSPHRASE" ]; then
  BUNDLE="$BACKUP_DIR/tessera-backup-$STAMP.tar.gz"
  ENCRYPTED="$BUNDLE.enc"
  (cd "$BACKUP_DIR" && tar -czf "tessera-backup-$STAMP.tar.gz" "postgres-$STAMP.dump" "evidence-$STAMP.tar.gz")
  BACKUP_ENCRYPTION_PASSPHRASE="$ENCRYPTION_PASSPHRASE" \
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
      -pass env:BACKUP_ENCRYPTION_PASSPHRASE -in "$BUNDLE" -out "$ENCRYPTED"
  rm -f "$BUNDLE"
  if [ "$ENCRYPTION_ONLY" = "1" ]; then
    rm -f "$BACKUP_DIR/postgres-$STAMP.dump" "$BACKUP_DIR/evidence-$STAMP.tar.gz"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$BACKUP_DIR" && sha256sum "tessera-backup-$STAMP.tar.gz.enc" > "SHA256SUMS-$STAMP")
  else
    (cd "$BACKUP_DIR" && shasum -a 256 "tessera-backup-$STAMP.tar.gz.enc" > "SHA256SUMS-$STAMP")
  fi
fi

if [ -n "$OFFSITE_DIR" ]; then
  mkdir -p "$OFFSITE_DIR"
  cp "$BACKUP_DIR/tessera-backup-$STAMP.tar.gz.enc" "$OFFSITE_DIR/"
  cp "$BACKUP_DIR/SHA256SUMS-$STAMP" "$OFFSITE_DIR/"
fi

find "$BACKUP_DIR" -type f \( -name 'postgres-*.dump' -o -name 'evidence-*.tar.gz' \) \
  -mtime +"$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -type f \( -name 'tessera-backup-*.tar.gz.enc' -o -name 'SHA256SUMS-*' \) \
  -mtime +"$RETENTION_DAYS" -delete

echo "backup complete: $BACKUP_DIR ($STAMP${ENCRYPTION_PASSPHRASE:+; encrypted}${OFFSITE_DIR:+; offsite: $OFFSITE_DIR})"
