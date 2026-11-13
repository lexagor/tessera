# Disaster-Recovery Drill

**Status:** procedure and recorded live checks. This is not a multi-AZ failover test.

## Safety

Use a disposable host/database and a copy of the backup. Never restore over production. Keep the
release manifest, database dump, evidence archive, and checksums together.

## Database restore

```bash
createdb tessera_restore_test
DATABASE_URL=postgres://tessera_app:...@host/tessera_restore_test \
  infra/scripts/restore-postgres.sh /var/backups/tessera/postgres-<stamp>.dump
psql "$DATABASE_URL" -c 'SELECT count(*) FROM schema_migrations;'
psql "$DATABASE_URL" -c 'SELECT count(*) FROM users;'
```

The restore must include migration `013` or later, RLS policies, and a valid `tessera_app` role.
Run `infra/scripts/check-rls.sh` against the restored database before exposing it.

## Evidence restore

```bash
infra/scripts/restore-evidence.sh /var/backups/tessera/evidence-<stamp>.tar.gz /tmp/evidence-restore
```

Then compare object keys in `evidence_packs` with files in the restored directory. If evidence
is in S3, restore/replicate the bucket and verify object versioning instead; the local archive is
not the source of truth.

## Smoke

1. Start API/broker against the restored database.
2. `/healthz`, `/readyz`, RLS check.
3. Auth0 login/logout with a test account.
4. Verify one receipt offline and open one reviewer link.
5. Build a new evidence pack and compare its archive to the restored files.
6. Record duration, row counts, missing objects, and the commit/image digests.

## Freshness check

```bash
BACKUP_DIR=/var/backups/tessera MAX_AGE_HOURS=26 infra/scripts/check-backup-freshness.sh
```

Run daily from cron/monitoring. A nonzero exit should page the operator. The check only proves a
recent file exists; the restore drill proves it is usable.

## Current gaps

- No multi-AZ/managed Postgres/Redis failover.
- No WAL/PITR on the live host.
- No automated evidence-volume restore into a clean host.
- No measured production RTO/RPO. See [`multi-az-dr.md`](multi-az-dr.md).
