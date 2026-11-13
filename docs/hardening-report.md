# Hardening report

**Date:** 2026-11-13  
**Base commit:** `828c8b9f`  
**Scope:** production configuration, auth/session, API edge, SSRF, webhook delivery, database
roles, observability, containers, and release metadata. External IdP/KMS/pen-test validation
is not included.

## Status

| Area | Status | Evidence |
|---|---|---|
| Production fail-closed config | Implemented | `apps/api/src/production-config.ts`, env tests, broker `production_problems` |
| OIDC state/identity/session | Implemented | `apps/api/src/oidc-state.ts`, `auth.ts`, migration `009_oidc_identity.sql` |
| CSRF and cookie hardening | Implemented | `apps/api/src/csrf.ts`, `__Host-` cookies, logout/write origin checks |
| API request limits | Implemented | `apps/api/src/index.ts`, `rate-limit.ts`, `body-limit`, request timeout |
| API shared rate limiting | Implemented | Redis limiter with local fallback; verified against local Redis |
| Security headers | Implemented | API headers plus Caddy HSTS/frame/referrer/permissions; CSP report-only |
| Webhook SSRF/DNS | Implemented | `safe-webhook.ts`; private/reserved checks, pinned lookup, redirect rejection |
| Webhook cross-replica delivery | Implemented | `010_webhook_delivery_leases.sql`, `FOR UPDATE SKIP LOCKED` lease |
| Broker redirects/egress | Implemented | `netguard.rs`; no redirects, strict-allowlist DNS checks |
| DB runtime role | Implemented | `postgres-init/001-app-role.sh`; production superuser startup refusal |
| API statement/lock timeouts | Implemented | `apps/api/src/db.ts` |
| Broker RLS | Verified locally | `infra/sql/rls.sql`, `docs/rls.md`, `rls_postgres` test, app-role query check |
| Control-plane RLS | Not implemented | Documented as application-enforced; do not claim otherwise |
| Scheduler leader | Implemented | Redis lease via `apps/broker/src/scheduler.rs` |
| Graceful shutdown | Implemented | API SIGTERM drain; broker graceful axum shutdown |
| Session/webhook cleanup | Implemented | Session idle cleanup; `WEBHOOK_RETENTION_DAYS` cleanup job |
| Observability | Baseline live; gaps remain | Structured logs + rotation, GitHub uptime workflow; `/metrics` and `alerts.yml` not scraped/deployed; no Sentry/status page |
| Backups | Live local schedule + restore drill; offsite missing | `infra/scripts/backup-docker.sh`, cron 03:15, logrotate; DB restore passed; no encrypted offsite/WAL/PITR |
| Containers | Implemented baseline | non-root API/static Caddy, cap drops, read-only app containers, limits, digest-pinned bases |
| Helm | Implemented baseline | read-only rootfs, seccomp, no broker Ingress, version `0.1.3` |
| Actions SHA pinning | Implemented | All workflow `uses:` refs pinned to commit SHAs |
| `cargo-deny` | Implemented and run | `deny.toml`, `security.yml` cargo-deny job, all checks pass |
| Dependency review | Implemented | `dependency-review-action` runs on pull requests |
| Image publishing | CI verified | GHCR images for API, broker, portal, verifier, and site; anonymous manifests return 200 |
| Image scanning | CI verified | Buildx + Trivy job passed for API and broker images |
| npm provenance / PyPI attestations | Implemented | Release workflow uses `--provenance` and trusted publishing with PEP 740 attestations; registry-side setup still required |
| Live OIDC | Live on Auth0 | Auth0 Regular Web Application; callback, domain allowlist, first-admin bootstrap, RP-initiated logout; dev tenant |
| SSH / host firewall | Implemented | Non-root deploy user, key-only auth, root `prohibit-password`, UFW, fail2ban active; root key break-glass remains |
| Cloud KMS/HSM + pen test | Not started | External dependency |

## P1 implementation snapshot

| Area | Status | Evidence |
|---|---|---|
| Evidence object storage | Code complete; optional | S3-compatible SigV4 adapter with local fallback; `EVIDENCE_S3_*`; no production bucket configured |
| Transactional email | Code complete; disabled | Resend HTTP adapter for invites/deletion notices; `EMAIL_PROVIDER=resend`; no live provider key |
| Tenant lifecycle | Code + runbook | JSON export, 30-day deletion request/cancel, retention setting; operator purge in `docs/data-lifecycle.md` |
| RLS automation | Implemented | `infra/scripts/check-rls.sh`; CI RLS step; 9 live broker tables verified |
| Control-plane RLS | Enabled live, tested | `015_control_plane_rls.sql`, `db.ts` context helpers, API/RLS tests, canary; rollback flag exists |
| Dependency updates | Config added | `renovate.json`, `docs/dependency-updates.md`; Renovate app installation pending |
| Load testing | Harness added | `scripts/load/authorize.mjs`, `docs/load-testing.md`; no staging host yet |
| Staging/rollback | Config + runbook | `docker-compose.staging.yml`, `docs/staging-rollback.md`; separate host/Auth0 app pending |
| Legal/trust | Published working docs | Privacy, terms, DPA, subprocessors, security contact targets; counsel/entity details pending |
| Billing messaging | Public prices removed | Billing remains disabled; site/docs no longer advertise a live price |
| WAF/DDoS | Partial | Caddy request-body cap and API rate limits; managed WAF/DDoS not deployed |
| Auth0 custom domain/email | Runbook only | Requires tenant admin access |
| KMS/HSM | Bridge/runbook; not migrated | Live still uses in-process key |
| `www` DNS | Documented | Intentionally absent; redirect if added |

## P2 implementation snapshot

| Area | Delivered | External/remaining |
|---|---|---|
| SOC 2 | Readiness control mapping, evidence cadence | Policies, auditor, operating period, report |
| Pen test | Scope, rules of engagement, coverage matrix | Independent tester, report, retest |
| KMS benchmark | `scripts/kms-bench.mjs`, test matrix | Real cloud KMS/HSM endpoint and key |
| Multi-AZ/DR | Target topology, RPO/RTO table, drill plan | Managed Postgres/Redis, second zone, measured failover |
| SCIM | Users endpoints, org tokens, Settings UI, tests, live smoke | SCIM Groups, deprovisioning automation, IdP certification |
| Enterprise SSO | Auth0 Organizations model documented | Per-customer configuration and custom Auth0 domain |
| Support/IR | Support policy, severity matrix, incident runbook | Contractual SLA, on-call rota, tabletop |
| Case study/reviewer | Consent and acceptance templates | Real customer/reviewer evidence |
| Independent review | Scope/package/questions | Engagement and report |
| Financial/fundraise | Calculator, assumptions template, checklist | Founder validation, legal/entity inputs |

## Verification snapshot

- API: 35 tests passing with local Postgres.
- Broker: 144 unit tests plus all integration suites passing; `cargo fmt` and `cargo clippy -D warnings` clean.
- Workspace: `pnpm typecheck`, `pnpm test`, `pnpm lint` passing.
- Redis limiter: allow/allow/deny verified against local Redis.
- Postgres init role: created and verified as `NOSUPERUSER NOBYPASSRLS`.
- Backup: daily backup ran on the live host; restore into a disposable database restored 11 migrations and one user.
- PITR: local WAL archiving + base backup restored to a target timestamp; the post-target row was absent.
- Offsite copy: the script supports `BACKUP_OFFSITE_DIR`, but no remote target is configured on the live host.
- Multi-replica: two brokers handled 20 concurrent authorizes with a verified 20-entry chain and elected one scheduler leader; two APIs shared the Redis auth limit and delivered one webhook exactly once.
- Helm chart rendered successfully with `helm template` (3 manifests, no Ingress).
- CI Security workflow built and Trivy-scanned API and broker images successfully.
- CI, Security, Images, and SBOM are green on `b5add27c`; Uptime manual run passed. P1/P2 CI/RLS checks passed on `828c8b9f`; live broker RLS 9/9; control-plane RLS canary passed; live SCIM and CSP checks passed.
- Caddy production config validates.
- Production compose config validates with a complete secret set.
- `pnpm install --frozen-lockfile` passes.

## Residual risks

1. Auth0 login and RP-initiated logout are live. Enterprise IdP validation (Okta/Entra) and a
   custom Auth0 domain remain; the temporary M2M app is disabled but not deleted.
2. Broker RLS is active on 9 tables and was re-applied after migration 011; no startup
   assertion exists. Control-plane tables remain application-enforced.
3. Local Docker was unavailable; images were built and Trivy-scanned in CI, so non-root
   runtime verification is covered there rather than on this machine.
4. npm provenance and PyPI trusted publishing are implemented in the tag workflow but require
   registry-side setup before the next release. GitHub Actions are pinned, dependency review
   runs on PRs, and `cargo-deny` passes locally and in CI.
5. Real remote offsite retention and measured restore timing remain operational validation; the
   live logical restore passed, while offsite/WAL/PITR and a clean-host drill remain.
6. Generated galleries/archives are at-least-once; webhook consumers must be idempotent.
7. `paste 1.0.15` is unmaintained transitively through `cel-interpreter`; `cargo-deny` records
   `RUSTSEC-2024-0436` as an accepted risk until the policy engine dependency changes.

## Claim boundaries

Safe wording: “production configuration is fail-closed; auth, session, SSRF, webhook, and
database-role hardening are implemented; broker RLS is verified locally and documented.” Do not claim
SOC 2, a completed external pen test, control-plane RLS, enterprise IdP/KMS validation, or
immutable storage.
