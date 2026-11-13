#!/bin/sh
set -eu

# Verify that every broker tenant table that exists has ENABLE + FORCE RLS and a policy.
# This is intentionally read-only. Run it after migrations/RLS application, before opening
# traffic. Missing optional tables are skipped (for example stripe_grants on a deployment
# that has not enabled broker-held Stripe grants).
#
#   DATABASE_URL=postgres://... infra/scripts/check-rls.sh
#   POSTGRES_CONTAINER=docker-postgres-1 POSTGRES_PASSWORD=... infra/scripts/check-rls.sh

TABLES="receipt_chain policies policy_versions stripe_grants telemetry_calls telemetry_fields revocations api_keys anchors anchor_targets"

if [ -n "${POSTGRES_CONTAINER:-}" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required with POSTGRES_CONTAINER}"
  psql_cmd() {
    docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" \
      psql -U "${POSTGRES_USER:-tessera}" -d "${POSTGRES_DB:-tessera}" -tAc "$1"
  }
else
  : "${DATABASE_URL:?DATABASE_URL or POSTGRES_CONTAINER is required}"
  psql_cmd() {
    psql "$DATABASE_URL" -tAc "$1"
  }
fi

present=0
failures=0
for table in $TABLES; do
  row=$(psql_cmd "SELECT c.relrowsecurity::int || ':' || c.relforcerowsecurity::int || ':' || (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='$table' AND c.relkind IN ('r','p')")
  [ -n "$row" ] || continue
  present=$((present + 1))
  enabled=${row%%:*}
  rest=${row#*:}
  forced=${rest%%:*}
  policies=${rest#*:}
  if [ "$enabled" != "1" ] || [ "$forced" != "1" ] || [ "$policies" -lt 1 ]; then
    echo "FAIL: $table rls=$enabled force=$forced policies=$policies"
    failures=$((failures + 1))
  else
    echo "ok: $table rls=on force=on policies=$policies"
  fi
done

if [ "$present" -eq 0 ] && [ "${RLS_REQUIRE_TABLES:-0}" = "1" ]; then
  echo "FAIL: no expected broker tenant tables found"
  exit 1
fi
if [ "$failures" -gt 0 ]; then
  echo "$failures RLS failure(s)"
  exit 1
fi
echo "RLS check ok ($present table(s) checked)"
