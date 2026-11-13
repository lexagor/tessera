#!/bin/sh
set -eu

# Guarded tenant purge. Default is a dry run. It removes control-plane rows, broker tenant rows,
# and local evidence objects. S3 evidence must be purged in the bucket (or explicitly acknowledged).
#
#   ORG_SLUG=acme APPLY=1 ORG_CONFIRM='Acme' LEGAL_HOLD_CLEARED=1 \
#     POSTGRES_CONTAINER=docker-postgres-1 POSTGRES_PASSWORD=... \
#     EVIDENCE_VOLUME=docker_evidence \
#     infra/scripts/purge-tenant.sh
#
# Required: ORG_SLUG, ORG_CONFIRM (exact workspace name), LEGAL_HOLD_CLEARED=1, and APPLY=1 to
# delete. Set S3_PURGE_ACK=<bucket> if EVIDENCE_S3_BUCKET is configured.

: "${ORG_SLUG:?ORG_SLUG is required}"
: "${ORG_CONFIRM:?ORG_CONFIRM must equal the workspace name (safety check)}"
APPLY="${APPLY:-0}"
LEGAL_HOLD_CLEARED="${LEGAL_HOLD_CLEARED:-0}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
EVIDENCE_VOLUME="${EVIDENCE_VOLUME:-}"
EVIDENCE_S3_BUCKET="${EVIDENCE_S3_BUCKET:-}"

if [ -n "${POSTGRES_CONTAINER:-}" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required with POSTGRES_CONTAINER}"
  psql_t() { docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U "${POSTGRES_USER:-tessera}" -d "${POSTGRES_DB:-tessera}" -tAc "$1"; }
  psql_apply() { docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U "${POSTGRES_USER:-tessera}" -d "${POSTGRES_DB:-tessera}" -v ON_ERROR_STOP=1 -f -; }
else
  : "${DATABASE_URL:?DATABASE_URL or POSTGRES_CONTAINER is required}"
  psql_t() { psql "$DATABASE_URL" -tAc "$1"; }
  psql_apply() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f -; }
fi

ORG_ROW=$(psql_t "SELECT id, name FROM orgs WHERE slug = '$ORG_SLUG' LIMIT 1")
ORG_ID=$(printf '%s' "$ORG_ROW" | cut -d'|' -f1)
ORG_NAME=$(printf '%s' "$ORG_ROW" | cut -d'|' -f2-)
[ -n "${ORG_ID:-}" ] || { echo "organization not found: $ORG_SLUG" >&2; exit 2; }
[ "$ORG_CONFIRM" = "$ORG_NAME" ] || { echo "ORG_CONFIRM does not match workspace name '$ORG_NAME'" >&2; exit 2; }
[ "$LEGAL_HOLD_CLEARED" = "1" ] || { echo "set LEGAL_HOLD_CLEARED=1 after confirming no legal hold" >&2; exit 2; }
if [ -n "$EVIDENCE_S3_BUCKET" ] && [ "${S3_PURGE_ACK:-}" != "$EVIDENCE_S3_BUCKET" ]; then
  echo "S3 evidence is configured; set S3_PURGE_ACK=$EVIDENCE_S3_BUCKET after purging the bucket prefix" >&2
  exit 2
fi

TENANTS=$(psql_t "SELECT broker_tenant FROM environments WHERE org_id = '$ORG_ID'")
printf 'org: %s (%s)\n' "$ORG_NAME" "$ORG_ID"
printf 'broker tenants:\n%s\n' "${TENANTS:-<none>}"
printf 'control-plane environments: %s\n' "$(psql_t "SELECT count(*) FROM environments WHERE org_id = '$ORG_ID'")"
printf 'actions: %s\n' "$(psql_t "SELECT count(*) FROM actions WHERE org_id = '$ORG_ID'")"
printf 'evidence packs: %s\n' "$(psql_t "SELECT count(*) FROM evidence_packs WHERE org_id = '$ORG_ID'")"
OBJECT_KEYS=$(psql_t "SELECT object_key FROM evidence_packs WHERE org_id = '$ORG_ID' AND object_key IS NOT NULL")
printf 'evidence objects: %s\n' "$(printf '%s\n' "$OBJECT_KEYS" | sed '/^$/d' | wc -l | tr -d ' ')"

if [ "$APPLY" != "1" ]; then
  echo "dry run only; set APPLY=1 and ORG_CONFIRM to purge"
  exit 0
fi

# Store the evidence locators before the cascade removes the pack rows.
printf '%s\n' "$OBJECT_KEYS" > /tmp/tessera-purge-evidence-keys.$$

# Build a safe SQL array literal from the broker tenants (generated identifiers, still escaped).
TENANT_ARRAY=$(printf '%s\n' "$TENANTS" | sed "/^$/d; s/'/''/g; s/^/'/; s/$/'/" | paste -sd, -)
[ -n "$TENANT_ARRAY" ] || TENANT_ARRAY="NULL"

# Delete broker tenant rows, then the control-plane org (cascades memberships, environments,
# actions, packs, webhooks, etc.).
psql_apply <<SQL
BEGIN;
DO \$\$
DECLARE t text;
DECLARE tenants text[] := ARRAY[$TENANT_ARRAY];
BEGIN
  FOR t IN
    SELECT table_name FROM information_schema.columns
     WHERE table_schema = 'public' AND column_name = 'tenant'
       AND table_name NOT LIKE 'receipt_chain_p_%'
  LOOP
    EXECUTE format('DELETE FROM %I WHERE tenant = ANY(\$1)', t) USING tenants;
  END LOOP;
END \$\$;
DELETE FROM orgs WHERE id = '$ORG_ID';
COMMIT;
SQL

# Remove local evidence objects. S3 was acknowledged above and is not touched by this script.
if [ -z "$EVIDENCE_S3_BUCKET" ] && [ -n "$EVIDENCE_VOLUME" ]; then
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    base=$(basename "$key")
    docker run --rm -v "$EVIDENCE_VOLUME:/data" postgres:16-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139 sh -c 'rm -f "/data/$1"' sh "$base" >/dev/null
  done < /tmp/tessera-purge-evidence-keys.$$
fi
rm -f /tmp/tessera-purge-evidence-keys.$$

echo "purged: $ORG_NAME ($ORG_SLUG) at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "record the purge in the operator change log; backups expire on their retention schedule."
