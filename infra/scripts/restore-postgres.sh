#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${1:?usage: restore-postgres.sh <postgres-*.dump>}"

pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" "$1"
echo "restore complete: $1"
