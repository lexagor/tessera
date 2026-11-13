# Incident Response Runbook

**Status:** operational draft. Test with a tabletop before a paid production commitment.

## Severity

| Severity | Examples | Target response | Target update |
|---|---|---|---|
| SEV-1 | Cross-tenant access, signing-key compromise, auth bypass, active data loss | 15 minutes acknowledgement; containment immediately | Every 60 minutes |
| SEV-2 | Privilege escalation, SSRF to internal service, evidence tampering, sustained outage | 1 hour | Every 4 hours |
| SEV-3 | Limited data exposure, failed backup, degraded non-critical feature | 1 business day | Daily |
| SEV-4 | Hardening gap, low-impact bug, documentation issue | 3 business days | Weekly |

These are internal targets, not a contractual SLA. Security reports use
[`security-sla.md`](security-sla.md).

## Roles

- **Incident commander:** owns timeline, decisions, and communication.
- **Security lead:** containment, evidence preservation, scope.
- **Service owner:** rollback, restore, and customer impact.
- **Communications lead:** customer/status updates and legal/privacy coordination.
- **Scribe:** timestamped log of actions and evidence.

One person may hold multiple roles in the pilot; name backups before an incident.

## Lifecycle

1. **Detect and record.** Capture alert/report, UTC time, reporter, affected domains, and
   initial severity. Open a private incident channel/ticket.
2. **Triage.** Confirm scope without destructive testing. Preserve logs, request IDs, image
   digests, DB state, and relevant audit events.
3. **Contain.** Revoke sessions/tokens/keys, disable the affected integration/webhook, rotate
   secrets, isolate the service, or roll back to the previous digest. Prefer containment that
   preserves evidence.
4. **Eradicate.** Patch, rotate, rebuild from a known-good image, and verify no persistence.
5. **Recover.** Restore data if needed, run RLS/ready/smoke checks, and monitor for recurrence.
6. **Notify.** Follow the DPA and legal advice. If personal data is involved, notify the
   controller without undue delay and within 72 hours of confirmation where required. Do not
   speculate about cause or scope in customer updates.
7. **Postmortem.** Within five business days for SEV-1/2: timeline, root cause, impact, what
   worked, corrective actions with owners/dates, and customer-safe summary. Blameless.
8. **Close.** Verify corrective actions, update threat model/controls, and archive evidence.

## First 30 minutes checklist

- [ ] Acknowledge and assign incident commander.
- [ ] Freeze deployments and destructive admin actions.
- [ ] Capture request IDs, logs, image digests, and DB/RLS state.
- [ ] Revoke exposed credentials and sessions.
- [ ] Determine whether tenant data or signing keys are involved.
- [ ] Notify security lead and, if needed, legal/privacy.
- [ ] Start a timestamped incident log.
- [ ] Decide rollback/restore with the service owner.

## Contacts

`security@thetessera.xyz` is the primary security contact. Maintain an offline copy of the
escalation tree, provider status pages, and break-glass access instructions outside the service.
Do not put secrets in the incident ticket.
