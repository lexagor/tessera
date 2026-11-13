# SOC 2 Readiness

**Status:** readiness plan and control index. Tessera is **not SOC 2 certified** and has not
completed a SOC 2 Type I or Type II examination.

## Scope

Candidate system description: hosted Tessera control plane, Rust broker, evidence storage,
public verifier, and supporting CI/operations. The first examination should cover the
production service at `app.thetessera.xyz`, `thetessera.xyz`, and `verify.thetessera.xyz`, not
the open-source repository alone.

Trust services criteria in scope for the first pass: **Security (common criteria)**, with
**Availability** and **Confidentiality** as likely additions once the service has a committed
SLA and more than one production region.

## Control readiness

| Area | Current control / evidence | Gap before Type I |
|---|---|---|
| Logical access (CC6) | Auth0 OIDC, RBAC, org-scoped sessions, `tessera_app` DB role, broker RLS, SCIM provisioning tokens | Formal access review calendar, joiner/mover/leaver records, MFA enforcement evidence |
| Change management (CC8) | Git history, protected `main`, CI typecheck/tests, RLS check, Security/SBOM/Images workflows, image digests | Branch protection export, release approvals, emergency-change procedure |
| Risk assessment (CC3) | `docs/threat-model.md`, `docs/controls-matrix.md`, due-diligence report | Dated risk register with owners and treatment decisions |
| Monitoring (CC7) | Structured logs, GitHub uptime, `/metrics`, RLS check, backup cron | Alert routing and retention, incident tickets, capacity review |
| Incident response (CC7) | `docs/incident-response.md`, security contact | Tabletop exercise, on-call rota, postmortem examples |
| Vendor management (CC9) | `docs/subprocessors.md`, DPA template | Signed subprocessor agreements and annual review evidence |
| Availability (A1) | Daily backups, restore drill, single VPS | Multi-AZ/managed DB, measured RTO/RPO, failover test |
| Confidentiality (C1) | Encrypted transport, encrypted secret storage, tenant isolation | Data classification, key management evidence, retention automation |
| Evidence integrity | EIP-712 receipts, hash chains, offline verifier, evidence packs | Independent review of receipt/chain boundaries |
| HR / entity controls | Founder-operated | Employment/contractor policy, background checks if required, org chart |

## Collect a snapshot

`infra/scripts/soc2-evidence.sh` writes a non-secret snapshot of the commit, CI runs, containers,
image digests, RLS result, backups, and host firewall/fail2ban status. Review it before sharing;
it is evidence metadata, not an audit opinion.

## Evidence cadence

- **Per release:** commit SHA, image digests, migration list, CI/Security/SBOM/RLS results,
  release manifest (`infra/releases/`).
- **Daily:** backup success, uptime checks, failed-login/fail2ban review.
- **Weekly:** dependency updates, vulnerability triage, access anomalies.
- **Monthly:** restore sample, disk/capacity review, subprocessor review, open-risk review.
- **Quarterly:** access review, tabletop incident, policy review, control self-assessment.
- **Annually:** penetration test, DR test, SOC 2 examination window.

## Type I path

1. Appoint a control owner and choose an auditor (readiness assessment first).
2. Adopt the draft policy set in [`security-policies.md`](security-policies.md): access, change,
   incident, backup, vendor, risk, acceptable use, retention, cryptography, and vulnerability
   management.
3. Run three months of evidence collection against the control matrix.
4. Close design gaps: HA/managed data tier, alerting, formal access reviews, audit logging
   retention, and a tested incident process.
5. Complete the readiness assessment and remediate findings.
6. Schedule the Type I observation date. Do not describe the result as certified until the
   report is issued and the report period is clear.
7. Plan Type II only after controls are operating repeatedly and evidence is automated.

## Auditor request pack

Prepare: system description, architecture diagram, data-flow diagram, control matrix, policy
set, subprocessor list, DPA, risk register, incident log, access-review evidence, change/release
records, backup/restore results, vulnerability scans, penetration-test report, and a list of
carve-outs. The current repository provides drafts for several of these, not an audit opinion.

## Claim boundary

Safe: “SOC 2 readiness control mapping, evidence packs, and operating procedures are in
progress.” Unsafe: “SOC 2 compliant,” “SOC 2 certified,” or “Type II audited” until an
independent CPA report exists.
