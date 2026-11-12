#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

failures=0
warn() { echo "WARN: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
ok() { echo "ok: $*"; }

for command in docker curl awk; do
  command -v "$command" >/dev/null 2>&1 || fail "missing required command: $command"
done
if command -v docker >/dev/null 2>&1; then
  docker compose version >/dev/null 2>&1 || fail "docker compose v2 is not available"
  ok "docker compose is available"
fi

for name in SITE_DOMAIN APP_DOMAIN VERIFY_DOMAIN ACME_EMAIL \
  OIDC_ISSUER OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_REDIRECT_URI OIDC_STATE_SECRET \
  CONTROL_PLANE_ENC_KEY TENANT_SECRET_ENC_KEY BROKER_SIGNING_KEY \
  BROKER_ADMIN_KEY BROKER_ADMIN_TOKEN TESSERA_ADMIN_TOKEN \
  TESSERA_AUTHORITY_HMAC_SECRET POSTGRES_PASSWORD POSTGRES_APP_PASSWORD \
  DATABASE_URL REDIS_URL; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || fail "missing required environment variable: $name"
done

if [ -r /proc/meminfo ]; then
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  [ "${mem_kb:-0}" -ge 3145728 ] || warn "less than 3 GB RAM detected; use pulled images and swap, do not build on the VPS"
fi

disk_kb=$(df -Pk / | awk 'NR==2 {print $4}')
[ "${disk_kb:-0}" -ge 10485760 ] || warn "less than 10 GB free disk; image pulls and backups may fail"

if command -v dig >/dev/null 2>&1; then
  for host in "${SITE_DOMAIN:-}" "${APP_DOMAIN:-}" "${VERIFY_DOMAIN:-}"; do
    [ -n "$host" ] || continue
    resolved=$(dig +short "$host" A | head -1)
    [ -n "$resolved" ] || fail "no A record for $host"
    if [ -n "${VPS_IP:-}" ] && [ "$resolved" != "$VPS_IP" ]; then
      fail "$host resolves to $resolved, expected $VPS_IP"
    fi
  done
else
  warn "dig is not installed; DNS was not checked"
fi

if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ':(80|443)$'; then
    warn "something is already listening on port 80 or 443"
  else
    ok "ports 80 and 443 appear free"
  fi
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures preflight failure(s)"
  exit 1
fi
echo "preflight ok"
