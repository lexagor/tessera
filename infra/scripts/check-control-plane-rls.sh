#!/bin/sh
set -eu

# Verify the control-plane RLS policies installed by migration 015.
# Read-only. Run after migrations; `CONTROL_PLANE_RLS` enforcement is a separate runtime flag.

TABLES="orgs memberships invites sessions environments agents agent_keys actions action_reviews usage_daily verification_links evidence_packs audit_log webhook_endpoints webhook_deliveries integration_connections billing_subscriptions scim_tokens"
if [ -n "${POSTGRES_CONTAINER:-}" ]; then
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required with POSTGRES_CONTAINER}"
  psql_cmd() { docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER" psql -U "${POSTGRES_USER:-tessera}" -d "${POSTGRES_DB:-tessera}" -tAc "$1"; }
else
  : "${DATABASE_URL:?DATABASE_URL or POSTGRES_CONTAINER is required}"
  psql_cmd() { psql "$DATABASE_URL" -tAc "$1"; }
fi

present=0
failures=0
for table in $TABLES; do
  row=$(psql_cmd "SELECT c.relrowsecurity::int || ':' || c.relforcerowsecurity::int || ':' || (SELECT count(*) FROM pg_policies p WHERE p.schemaname='public' AND p.tablename=c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='$table' AND c.relkind IN ('r','p')")
  [ -n "$row" ] || continue
  present=$((present + 1))
  enabled=${row%%:*}; rest=${row#*:}; forced=${rest%%:*}; policies=${rest#*:}
  if [ "$enabled" != "1" ] || [ "$forced" != "1" ] || [ "$policies" -lt 1 ]; then
    echo "FAIL: $table rls=$enabled force=$forced policies=$policies"
    failures=$((failures + 1))
  else
    echo "ok: $table rls=on force=on policies=$policies"
  fi
done
if [ "$present" -eq 0 ] && [ "${RLS_REQUIRE_TABLES:-0}" = "1" ]; then
  echo "FAIL: no control-plane tables found"
  exit 1
fi
if [ "$failures" -gt 0 ]; then echo "$failures control-plane RLS failure(s)"; exit 1; fi
echo "control-plane RLS check ok ($present table(s) checked)"
