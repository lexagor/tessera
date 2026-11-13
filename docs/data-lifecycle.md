# Tenant Data Lifecycle

**Last updated:** 2026-11-13

Tessera separates control-plane data (Postgres), broker truth (Postgres broker tables and
receipt chains), evidence objects (local volume or S3-compatible storage), and backups. A
tenant deletion is not complete until all four are handled.

## Export

Workspace owners and admins can download a JSON export:

```bash
curl -fsS -b "tessera_session=..." \
  https://app.thetessera.xyz/v1/org/export \
  -o tessera-export.json
```

The export contains organization metadata, members, invites, environments, agents, the action
read model, audit events, usage, and webhook endpoint metadata. It deliberately excludes
secrets, broker keys, webhook signing secrets, and session tokens. Action and audit exports
are capped at 10,000 rows; evidence packs remain the complete signed record.

Export before requesting deletion. The API records an `org.exported` audit event.

## Deletion request

An owner can record a deletion request in Settings or with:

```bash
curl -X POST https://app.thetessera.xyz/v1/org/deletion-request \
  -H 'content-type: application/json' \
  -b "tessera_session=..." \
  -d '{"confirm":"Workspace Name"}'
```

This sets a 30-day grace period. It does **not** automatically delete anything. The owner can
cancel before the purge date. An email is sent to the requesting owner when email delivery is
configured.

## Operator purge

After the purge date, an operator must run the purge deliberately. The repository does not
expose an internet-facing hard-delete endpoint because broker receipts and anchors have
retention and legal-hold implications.

`infra/scripts/purge-tenant.sh` performs a guarded dry run by default and requires
`APPLY=1`, an exact workspace-name confirmation, and `LEGAL_HOLD_CLEARED=1`. It deletes broker
tenant rows, cascades the control-plane organization, and removes local evidence objects. If
`EVIDENCE_S3_BUCKET` is set, the operator must purge the bucket prefix separately and acknowledge
it with `S3_PURGE_ACK=<bucket>`.

1. Confirm the request is past `deletion_scheduled_for` and no legal hold applies.
2. Export any final evidence required by contract or law.
3. Run the dry run and review counts:

   ```bash
   ORG_SLUG=acme ORG_CONFIRM='Acme' LEGAL_HOLD_CLEARED=1 \
     POSTGRES_CONTAINER=docker-postgres-1 POSTGRES_PASSWORD=... \
     EVIDENCE_VOLUME=docker_evidence infra/scripts/purge-tenant.sh
   ```

4. Apply with the same environment plus `APPLY=1`.
5. Remove the organization from backups according to the backup retention schedule.
6. Record the purge in the operator change log with counts and date.

The script does not delete the global user identities; membership and tenant data are removed.
Backups can retain a copy until their retention window expires.

```sql
-- Inspect first; do not run blindly.
SELECT id, name, deletion_requested_at, deletion_scheduled_for
  FROM orgs WHERE deletion_scheduled_for IS NOT NULL;
```

## Retention

`orgs.retention_days` defaults to 365 and can be set by an owner from 30–3650 days. It is a
policy input for the operator's retention job; it is not an automatic hard-delete timer.
Session and webhook-delivery cleanup are automatic. Evidence packs are not pruned by the API;
the operator must apply the configured retention period.

## Backups

A deleted tenant may remain in backups until the backup retention window expires. The current
runbook keeps local daily backups for 30 days; offsite retention is deployment-specific. State
this in the DPA and privacy policy, and do not promise immediate erasure from immutable
backups unless the backup target supports it.
