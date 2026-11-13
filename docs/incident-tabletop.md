# Incident Tabletop Scenario

**Status:** facilitator guide. Schedule one tabletop before a paid production commitment.

## Scenario

A customer reports that an action from workspace A appears in a verification page for workspace
B. The report includes a reviewer link and a redacted receipt ID. At the same time, an alert
shows elevated 5xx responses on `app.thetessera.xyz`.

## Inject schedule

1. **T+0:** Customer report and 5xx alert. Assign incident commander and scribe.
2. **T+10:** Confirm whether the link is expired/revoked; preserve request IDs, logs, DB/RLS
   state, and image digests. Do not ask the customer for more data yet.
3. **T+20:** Decide containment: revoke the link/session/SCIM token, disable webhook endpoint,
   or roll back to the previous release digest.
4. **T+35:** Determine blast radius: which tenants/tables/receipts; whether signing keys or
   evidence objects are involved; whether backups contain the affected data.
5. **T+50:** Draft customer/status update and legal/privacy notification decision.
6. **T+70:** Recovery: patch/restore, RLS checks, `/readyz`, verification and reviewer-link
   checks.
7. **Close:** Schedule postmortem within five business days; assign corrective actions.

## Questions to test

- Who can revoke a reviewer link, session, SCIM token, broker key, and webhook independently?
- Where are request IDs, RLS state, image digests, and audit events preserved?
- Can we restore a single tenant or only the whole database?
- What evidence proves the cross-tenant page was not caused by a cached/shared response?
- Who decides whether the 72-hour breach notification clock starts?
- Does the customer update avoid speculation and unsupported certification claims?

## Success criteria

- Commander and scribe assigned within 15 minutes.
- Containment decision and blast-radius owner identified within 45 minutes.
- Customer update reviewed for accuracy and claim boundaries.
- Postmortem actions have owners/dates and link to the control matrix.

Record the date, participants, decisions, gaps, and follow-ups. Do not include real customer
identity or secrets in the exercise notes.
