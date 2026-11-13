#!/bin/sh
set -eu

ENV_FILE="${ENV_FILE:-/opt/tessera/infra/docker/.env}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-docker-postgres-1}"
EVIDENCE_VOLUME="${EVIDENCE_VOLUME:-docker_evidence}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
OFFSITE_DIR="${BACKUP_OFFSITE_DIR:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

: "${ENV_FILE:?ENV_FILE is required}"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"

mkdir -p "$BACKUP_DIR"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
  pg_dump -U tessera -Fc -d tessera -f "/tmp/postgres-$STAMP.dump"
docker cp "$POSTGRES_CONTAINER:/tmp/postgres-$STAMP.dump" "$BACKUP_DIR/postgres-$STAMP.dump"
docker exec "$POSTGRES_CONTAINER" rm -f "/tmp/postgres-$STAMP.dump"

docker run --rm \
  -v "$EVIDENCE_VOLUME:/data:ro" \
  -v "$BACKUP_DIR:/backup" \
  postgres:16-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139 \
  tar -czf "/backup/evidence-$STAMP.tar.gz" -C /data .

if [ -n "$OFFSITE_DIR" ]; then
  mkdir -p "$OFFSITE_DIR"
  cp "$BACKUP_DIR/postgres-$STAMP.dump" "$OFFSITE_DIR/"
  cp "$BACKUP_DIR/evidence-$STAMP.tar.gz" "$OFFSITE_DIR/"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OFFSITE_DIR" && sha256sum "postgres-$STAMP.dump" "evidence-$STAMP.tar.gz" > "SHA256SUMS-$STAMP")
  else
    (cd "$OFFSITE_DIR" && shasum -a 256 "postgres-$STAMP.dump" "evidence-$STAMP.tar.gz" > "SHA256SUMS-$STAMP")
  fi
fi

find "$BACKUP_DIR" -type f \( -name 'postgres-*.dump' -o -name 'evidence-*.tar.gz' \) \
  -mtime +"$RETENTION_DAYS" -delete

echo "backup complete: $BACKUP_DIR ($STAMP${OFFSITE_DIR:+; offsite: $OFFSITE_DIR})"
