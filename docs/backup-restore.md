# Backup and restore

This is the operator runbook for production data. It covers Postgres, the evidence volume,
offsite copies, and a restore drill.

## Scope and targets

| Data | Method | Suggested RPO | Suggested RTO |
|---|---|---:|---:|
| Postgres control plane + broker tables | Daily logical dump; optional WAL/PITR | 24 h logical / <15 min PITR | 1 h |
| Evidence volume | Daily archive; offsite copy | 24 h | 1 h |
| Secrets and configuration | Operator secret store backup | changes only | 1 h |

The API and broker are stateless; they are redeployed from the image and the restored data.
These targets are starting points: confirm them against the design-partner SLA before
publishing them externally.

## Logical backup

`infra/scripts/backup.sh` writes a custom-format Postgres dump and an evidence archive:

```bash
DATABASE_URL="$DATABASE_URL" \
EVIDENCE_DIR=/data/evidence \
BACKUP_DIR=/var/backups/tessera \
BACKUP_RETENTION_DAYS=30 \
infra/scripts/backup.sh
```

Schedule it from the host or a sidecar. Keep the dump and evidence archive together; an
archive without its evidence volume is incomplete.

## Offsite copy

Set `BACKUP_OFFSITE_DIR` to a mounted remote/backup target to have the script copy the dump,
evidence archive, and SHA-256 manifest there. For example, with an operator-installed
`rclone`:

```bash
rclone copy /var/backups/tessera remote:tessera-backups/$(date -u +%Y/%m/%d) --immutable
```

Do not put long-lived storage credentials in the application containers. Use a host-level
backup identity.

## Postgres PITR

For a stricter RPO, enable WAL archiving on the production Postgres instance and ship WAL
segments offsite. A logical dump is still useful for cross-version restore tests. At minimum:

- set `archive_mode=on`, `archive_command` to an offsite-safe command, and `wal_level=replica`;
- retain base backups plus WAL for the approved window;
- test PITR into a disposable database before relying on it.

## Restore drill

Restore a logical dump into a fresh database:

```bash
createdb tessera_restore_test
DATABASE_URL=postgres://tessera_app:...@host/tessera_restore_test \
  infra/scripts/restore-postgres.sh /var/backups/tessera/postgres-<stamp>.dump
```

Then verify:

```bash
psql "$DATABASE_URL" -c 'SELECT count(*) FROM schema_migrations;'
psql "$DATABASE_URL" -c 'SELECT count(*) FROM receipt_chain;'
```

Restore the evidence volume by extracting the matching archive into `EVIDENCE_DIR` before
starting the API. Evidence pack paths are stored in the database, so the archive and database
must come from the same backup window.

After restore:

1. start the API and broker against the restored database;
2. check `/readyz`;
3. open one verification link and verify one receipt offline;
4. regenerate a signed evidence export and confirm the archive index/digests;
5. record the drill date, restore duration, row counts, and any mismatch.

## Freshness and DR drill

Run `infra/scripts/check-backup-freshness.sh` daily; it fails if the database or evidence archive
is older than the configured threshold. Run the clean-host procedure in
[`dr-drill.md`](dr-drill.md) monthly/quarterly and record the result.

## Failure notes

- A superuser `DATABASE_URL` is rejected in production; use `tessera_app`.
- `CONTROL_PLANE_ENC_KEY` must match the key used when broker credentials were encrypted.
  Rotating it without re-encryption makes stored credentials unreadable.
- Evidence archives are not pruned by the API. Apply the documented retention policy and keep
  backups outside the live volume.

## S3 evidence storage

If `EVIDENCE_S3_BUCKET` is configured, evidence packs are written to the bucket and the local
`docker_evidence` archive is not the source of truth. Back up the bucket with versioning and
replication (or an object-store lifecycle policy), test object restore separately, and keep the
Postgres dump with the bucket snapshot. The control-plane dump stores an `s3://bucket/key`
locator for each pack; restoring the database without the bucket loses archive downloads.
