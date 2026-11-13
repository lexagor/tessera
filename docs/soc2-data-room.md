# SOC 2 Data Room Index

**Status:** preparation index. No auditor report exists.

| Artifact | Location | Owner | Status |
|---|---|---|---|
| System description | `docs/architecture.md`, `docs/trust-center.md` | Founder | Draft |
| Control matrix | `docs/controls-matrix.md`, `docs/soc2-readiness.md` | Security owner | Draft |
| Policy set | `docs/security-policies.md` | Founder | Draft; counsel review |
| Risk register | `docs/threat-model.md`, due-diligence/risk notes | Founder | Draft; owners/TTL needed |
| Access review | Auth0/DB/SCIM/API-key exports | Security owner | Procedure; first review pending |
| Change/release records | Git history, `infra/releases/` | Engineering | Active |
| CI/security evidence | GitHub Actions runs, CodeQL, Scorecard, SBOM | Engineering | Active |
| RLS evidence | `check-rls.sh`, `check-control-plane-rls.sh`, tests | Engineering | Active |
| Backup/restore | `backup-docker.sh`, `dr-drill.md` records | Operations | Local drill passed; clean host pending |
| Incident evidence | `incident-response.md`, incident tickets | Security owner | Runbook; tabletop needed |
| Vendor/subprocessor | `subprocessors.md`, DPAs | Founder | Draft |
| Customer commitments | DPA, terms, SLA/support policy | Founder | Draft |
| Pen test | `pentest-scope.md`, report/retest | Security owner | Not engaged |
| SOC 2 report | Auditor | Founder | Not started |

Do not put secrets, raw customer data, or unredacted incident evidence in the data room. Export
evidence snapshots with `infra/scripts/soc2-evidence.sh` and review them before sharing.
