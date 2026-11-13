#!/bin/sh
set -eu

# Collect a non-secret, timestamped SOC 2 evidence snapshot. Review and redact before sharing.
OUT="${1:-/tmp/tessera-soc2-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

git rev-parse HEAD > "$OUT/git-sha.txt" 2>/dev/null || echo "not a git worktree" > "$OUT/git-sha.txt"
git status --short > "$OUT/git-status.txt" || true
git log -1 --format='%H%n%an%n%ad%n%s' > "$OUT/git-last-commit.txt" || true

if command -v gh >/dev/null 2>&1; then
  gh run list --limit 30 --json name,headSha,status,conclusion,createdAt \
    > "$OUT/github-runs.json" 2>/dev/null || true
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' > "$OUT/containers.tsv" || true
  docker images --digests --format '{{.Repository}}\t{{.Tag}}\t{{.Digest}}' > "$OUT/images.tsv" || true
fi

if [ -n "${DATABASE_URL:-}" ] || [ -n "${POSTGRES_CONTAINER:-}" ]; then
  RLS_REQUIRE_TABLES="${RLS_REQUIRE_TABLES:-1}" \
    sh "$(dirname "$0")/check-rls.sh" > "$OUT/rls-check.txt" 2>&1 || true
fi

BACKUP_DIR="${BACKUP_DIR:-/var/backups/tessera}"
if [ -d "$BACKUP_DIR" ]; then
  ls -lh "$BACKUP_DIR" > "$OUT/backups.txt" 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active fail2ban > "$OUT/fail2ban-status.txt" 2>/dev/null || true
  ufw status > "$OUT/ufw-status.txt" 2>/dev/null || true
fi

cat > "$OUT/README.txt" <<'TXT'
Tessera SOC 2 evidence snapshot.
Contains configuration and status metadata only; verify no secrets are present before sharing.
Pair with CI/Security/SBOM/Images run URLs, the release manifest, and the control matrix.
TXT

echo "evidence snapshot: $OUT"
