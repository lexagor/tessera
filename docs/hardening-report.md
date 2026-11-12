# Hardening report

**Date:** 2026-11-12  
**Base commit:** `81da683e`  
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
| Broker RLS script | Available, deployment step | `infra/sql/rls.sql`, `docs/rls.md`, `rls_postgres` test |
| Control-plane RLS | Not implemented | Documented as application-enforced; do not claim otherwise |
| Scheduler leader | Implemented | Redis lease via `apps/broker/src/scheduler.rs` |
| Graceful shutdown | Implemented | API SIGTERM drain; broker graceful axum shutdown |
| Session/webhook cleanup | Implemented | Session idle cleanup; `WEBHOOK_RETENTION_DAYS` cleanup job |
| Observability | Implemented baseline | `/metrics`, structured request logs, `infra/observability/alerts.yml` |
| Backups | Implemented baseline | `infra/scripts/backup.sh`, `restore-postgres.sh`, `docs/backup-restore.md` |
| Containers | Implemented baseline | non-root API/static Caddy, cap drops, read-only app containers, limits, digest-pinned bases |
| Helm | Implemented baseline | read-only rootfs, seccomp, no broker Ingress, version `0.1.3` |
| Actions SHA pinning | Implemented | All workflow `uses:` refs pinned to commit SHAs |
| Dependency review | Implemented | `dependency-review-action` runs on pull requests |
| Image scanning / cargo deny | Not implemented | Docker daemon unavailable; base images are digest-pinned, but no scanner/cargo-deny yet |
| npm/PyPI provenance | Not implemented | Release workflow still uses token-gated publishing if configured |
| Live OIDC/KMS/pen test | Not started | External dependency |

## Verification snapshot

- API: 24 tests passing with local Postgres.
- Broker: 144 unit tests plus all integration suites passing; `cargo fmt` and `cargo clippy -D warnings` clean.
- Workspace: `pnpm typecheck`, `pnpm test`, `pnpm lint` passing.
- Redis limiter: allow/allow/deny verified against local Redis.
- Postgres init role: created and verified as `NOSUPERUSER NOBYPASSRLS`.
- Backup: logical dump created from local Postgres; restore into a fresh database restored 10 migrations.
- Caddy production config validates.
- Production compose config validates with a complete secret set.
- `pnpm install --frozen-lockfile` passes.

## Residual risks

1. Live OIDC provider behavior (Okta/Entra/Auth0), account linking, and logout are validated
   only against the mock OIDC server. Run a real tenant before external publication.
2. Broker RLS is available but must be applied after the first broker migration. Control-plane
   tables remain application-enforced.
3. Docker images were not built here (no Docker daemon); image scanning and non-root runtime
   verification remain to be run in CI/host.
4. `cargo deny`, image scanning, npm provenance, and PyPI trusted publishing remain P2 work.
   GitHub Actions are now pinned to commit SHAs and dependency review runs on PRs.
5. Backup/PITR is documented and logical restore was drilled; WAL archiving/offsite retention
   and a two-replica load test remain operational validation.
6. Generated galleries/archives are at-least-once; webhook consumers must be idempotent.

## Claim boundaries

Safe wording: “production configuration is fail-closed; auth, session, SSRF, webhook, and
database-role hardening are implemented; broker RLS is available and documented.” Do not claim
SOC 2, a completed external pen test, control-plane RLS, live IdP/KMS validation, or immutable
storage.
