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
| Broker RLS | Verified locally | `infra/sql/rls.sql`, `docs/rls.md`, `rls_postgres` test, app-role query check |
| Control-plane RLS | Not implemented | Documented as application-enforced; do not claim otherwise |
| Scheduler leader | Implemented | Redis lease via `apps/broker/src/scheduler.rs` |
| Graceful shutdown | Implemented | API SIGTERM drain; broker graceful axum shutdown |
| Session/webhook cleanup | Implemented | Session idle cleanup; `WEBHOOK_RETENTION_DAYS` cleanup job |
| Observability | Implemented baseline | `/metrics`, structured request logs, `infra/observability/alerts.yml` |
| Backups | Implemented baseline | `infra/scripts/backup.sh`, `restore-postgres.sh`, `docs/backup-restore.md` |
| Containers | Implemented baseline | non-root API/static Caddy, cap drops, read-only app containers, limits, digest-pinned bases |
| Helm | Implemented baseline | read-only rootfs, seccomp, no broker Ingress, version `0.1.3` |
| Actions SHA pinning | Implemented | All workflow `uses:` refs pinned to commit SHAs |
| `cargo-deny` | Implemented and run | `deny.toml`, `security.yml` cargo-deny job, all checks pass |
| Dependency review | Implemented | `dependency-review-action` runs on pull requests |
| Image scanning | CI implemented, not run locally | Buildx + Trivy job for API and broker; no local Docker daemon |
| npm/PyPI provenance | Not implemented | Release workflow still uses token-gated publishing if configured |
| Live OIDC/KMS/pen test | Not started | External dependency |

## Verification snapshot

- API: 24 tests passing with local Postgres.
- Broker: 144 unit tests plus all integration suites passing; `cargo fmt` and `cargo clippy -D warnings` clean.
- Workspace: `pnpm typecheck`, `pnpm test`, `pnpm lint` passing.
- Redis limiter: allow/allow/deny verified against local Redis.
- Postgres init role: created and verified as `NOSUPERUSER NOBYPASSRLS`.
- Backup: logical dump created from local Postgres; restore into a fresh database restored 10 migrations.
- PITR: local WAL archiving + base backup restored to a target timestamp; the post-target row was absent.
- Multi-replica: two brokers handled 20 concurrent authorizes with a verified 20-entry chain and elected one scheduler leader; two APIs shared the Redis auth limit and delivered one webhook exactly once.
- Helm chart rendered successfully with `helm template` (3 manifests, no Ingress).
- Caddy production config validates.
- Production compose config validates with a complete secret set.
- `pnpm install --frozen-lockfile` passes.

## Residual risks

1. Live OIDC provider behavior (Okta/Entra/Auth0), account linking, and logout are validated
   only against the mock OIDC server. Run a real tenant before external publication.
2. Broker RLS is verified locally, but must still be applied in each target deployment after
   the first broker migration. Control-plane tables remain application-enforced.
3. Docker images were not built here (no Docker daemon); non-root runtime verification and
   image scanning must run in CI or on the target host.
4. Image scanning is wired into CI but was not run here; npm provenance and PyPI trusted
   publishing remain P2 work. GitHub Actions are pinned, dependency review runs on PRs, and
   `cargo-deny` passes locally.
5. Real offsite retention and measured restore timing remain operational validation; the local
   logical restore and PITR drills passed.
6. Generated galleries/archives are at-least-once; webhook consumers must be idempotent.
7. `paste 1.0.15` is unmaintained transitively through `cel-interpreter`; `cargo-deny` records
   `RUSTSEC-2024-0436` as an accepted risk until the policy engine dependency changes.

## Claim boundaries

Safe wording: “production configuration is fail-closed; auth, session, SSRF, webhook, and
database-role hardening are implemented; broker RLS is verified locally and documented.” Do not claim
SOC 2, a completed external pen test, control-plane RLS, live IdP/KMS validation, or immutable
storage.
