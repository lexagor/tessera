#!/bin/sh
set -eu

# Host-level checks for cron/monitoring. Prints a short status and exits nonzero on a hard failure.
ENV_FILE="${ENV_FILE:-/opt/tessera/infra/docker/.env}"
BASE_URL="${BASE_URL:-https://app.thetessera.xyz}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-docker-postgres-1}"
[ -r "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }

failed=0
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$BASE_URL/readyz" || true)"
[ "$code" = "200" ] || { echo "FAIL readyz=$code"; failed=1; }
echo "readyz=$code"

if [ -x "$(dirname "$0")/check-backup-freshness.sh" ]; then
  if ! BACKUP_DIR="$BACKUP_DIR" sh "$(dirname "$0")/check-backup-freshness.sh"; then failed=1; fi
fi
if [ -n "${POSTGRES_CONTAINER:-}" ] && [ -n "${POSTGRES_PASSWORD:-}" ]; then
  if ! POSTGRES_CONTAINER="$POSTGRES_CONTAINER" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" RLS_REQUIRE_TABLES=1 \
    sh "$(dirname "$0")/check-control-plane-rls.sh"; then failed=1; fi
fi

disk="$(df -Pk / | awk 'NR==2 {print $5}' | tr -d '%')"
[ "${disk:-100}" -lt 85 ] || { echo "FAIL disk=${disk}%"; failed=1; }
echo "disk=${disk}%"

for name in docker-api-1 docker-broker-1 docker-postgres-1 docker-caddy-1; do
  running="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$name" 2>/dev/null || true)"
  if [ "$running" != "running" ]; then
    echo "FAIL $name=$running"; failed=1; continue
  fi
  case "$health" in
    ""|healthy) : ;;
    starting) echo "WARN $name=$health" ;;
    *) echo "FAIL $name=$health"; failed=1 ;;
  esac
done

exit "$failed"
