#!/bin/sh
set -eu

# Restore an evidence archive into an empty directory and verify it is readable.
# Usage: restore-evidence.sh <evidence-*.tar.gz> <target-dir>
ARCHIVE="${1:?usage: restore-evidence.sh <evidence-*.tar.gz> <target-dir>}"
TARGET="${2:?usage: restore-evidence.sh <evidence-*.tar.gz> <target-dir>}"

[ -f "$ARCHIVE" ] || { echo "archive not found: $ARCHIVE" >&2; exit 2; }
if [ -d "$TARGET" ] && [ "$(find "$TARGET" -mindepth 1 -maxdepth 1 | head -1)" ]; then
  echo "refusing to restore into non-empty directory: $TARGET" >&2
  exit 2
fi
mkdir -p "$TARGET"
tar -tzf "$ARCHIVE" >/dev/null
tar -xzf "$ARCHIVE" -C "$TARGET"
count=$(find "$TARGET" -type f | wc -l | tr -d ' ')
echo "evidence restore complete: $count file(s) in $TARGET"
