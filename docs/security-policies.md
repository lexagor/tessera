# Security Policy Set (Draft)

**Status:** founder-approved draft pending legal/security review. Effective date: 2026-11-13.
These policies support SOC 2 readiness; they are not an audit report.

## Governance and risk

- The founder is the interim security owner and approves exceptions.
- Review the threat model, controls matrix, vendor list, and open risks at least quarterly.
- Record risks with owner, likelihood/impact, treatment, due date, and evidence.
- Material changes to auth, signing, tenant isolation, or data deletion require a written
  change record and rollback plan.

## Access control

- Use unique accounts, MFA for Auth0/Cloud/GitHub administration, and least privilege.
- Production root access is break-glass only; prefer the non-root deploy user.
- Review workspace members, SCIM tokens, API keys, and cloud roles quarterly and on offboarding.
- Revoke access within one business day of a role change or termination.
- Shared credentials are prohibited; secrets live in a secret store and are rotated on exposure.

## Change management

- All code changes go through Git and CI: typecheck, tests, RLS check, Security, SBOM, Images.
- Production deploys use digest-pinned images and a release manifest.
- Database migrations are forward-only and reviewed; back up before destructive changes.
- Emergency changes require incident-commander approval and a retrospective record.
- Do not deploy with failing critical/high security checks; document any approved exception.

## Cryptography and key management

- TLS 1.2+ in transit; HSTS at the edge.
- Secrets at rest encrypted; `CONTROL_PLANE_ENC_KEY`, `TENANT_SECRET_ENC_KEY`, HMAC and signing
  keys are high-sensitivity and backed up in the operator secret store.
- Prefer KMS/HSM custody for production signing; in-process keys are a pilot limitation.
- Rotate on exposure, personnel change, or scheduled policy; preserve verification history.
- Receipts are tamper-evident, not tamper-proof; do not claim otherwise.

## Vulnerability management

- Dependabot/Renovate or weekly review; patch critical/high issues on a risk-based timeline.
- CI runs dependency audit, `cargo-deny`, image scans, and SBOM generation.
- Track exceptions with rationale and expiry; do not silently ignore critical findings.
- External penetration test before a paid production commitment where feasible.

## Logging and monitoring

- Structured JSON logs with request IDs; do not log secrets, tokens, or full provider payloads.
- Retain operational logs per the retention policy; protect integrity and restrict access.
- Alert on availability, 5xx/latency, auth anomalies, failed backups, disk, and certificate expiry.
- Review access and security alerts at least weekly.

## Backup and resilience

- Daily logical Postgres dump and evidence backup; verify restore at least monthly.
- Copy backups off-host with encryption and retention; test a clean-host restore quarterly.
- Define RPO/RTO for each data class; measure failover and record results.
- Restore drills must include RLS, signature verification, and a reviewer-link check.

## Vendor and subprocessor management

- Maintain `docs/subprocessors.md`; review security terms before adding a subprocessor.
- Prefer providers with independent reports and documented incident notification.
- Review vendor access and data flows annually and on material change.
- Customer DPAs flow down equivalent obligations.

## Data retention and deletion

- Default workspace retention is 365 days; owners can set 30–3650 days.
- Deletion requests have a 30-day grace period; purge is an operator workflow.
- Backups expire on their retention schedule; disclose this limitation.
- Do not retain customer content beyond contract, law, or security needs.

## Acceptable use and personnel

- Production access is limited to authorized operators; no personal use of customer data.
- Contractors with production access sign confidentiality/IP terms and complete security
  onboarding.
- Report suspected incidents immediately to `security@thetessera.xyz`.
- Violations may result in access removal and contract action.

## Review and exceptions

Review this policy set annually and after a material incident or architecture change. Exceptions
must be documented, time-limited, approved by the security owner, and linked to compensating
controls.
