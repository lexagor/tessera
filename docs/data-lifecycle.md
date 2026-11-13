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

1. Confirm the request is past `deletion_scheduled_for` and no legal hold applies.
2. Export any final evidence required by contract or law.
3. Revoke the environment broker keys and agent keys.
4. Delete broker tenant rows through the broker's tenant-scoped admin path, or use the
   documented database procedure for the deployment.
5. Delete evidence objects for the tenant (`EVIDENCE_DIR` or the S3 prefix).
6. Delete the control-plane organization; cascades remove memberships, environments, actions,
   packs, webhooks, and audit rows. Users remain as identities.
7. Remove the organization from backups according to the backup retention schedule.
8. Record the purge in the operator incident/change log with counts and date.

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
