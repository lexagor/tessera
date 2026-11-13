# Tessera — Product & Technical Due Diligence

**Date:** 2026-11-13  
**Repository:** `lexagor/tessera`  
**Code state:** `2989db82` (working tree also contains pre-existing investor-doc/design changes)  
**Live deployment:** `https://app.thetessera.xyz` on IONOS VPS `198.71.63.45`  
**Method:** source review, live endpoint checks, SSH host inspection, database checks, CI history,
and live Auth0/control-plane validation.

## Verdict

| Question | Answer |
|---|---|
| Is this a credible working demo? | **Yes** |
| Is it ready for a controlled design partner? | **Conditional** — P0/P1 code is in place; offsite backup, external monitoring/error tracking, KMS, and Auth0 cleanup remain |
| Is it ready for public / self-serve production? | **No** |
| Is it enterprise procurement-ready? | **No** — no SOC 2, external pen test, KMS/HSM deployment, HA, or DPA |

The technical core is materially stronger than the operational shell around it. The broker,
receipt, verifier, authority binding, RLS, and test coverage are real. The largest risks are now
offsite backup, observability/error tracking, rollback retention, Auth0 cleanup, and product/GTM proof.

**Current live state:** one user, one org, zero environments after the smoke check; Auth0 login
is live; broker and API are healthy; Postgres runs as `tessera_app` with broker RLS active (9
broker tables forced); images are digest-pinned; local backups and uptime checks are scheduled.

## What is working

- Auth0 Regular Web Application is live with callback, dashboard origins, authorization-code
  flow, RS256 tokens, and domain allowlist.
- `devAuth` is off; broker demo mode is off; API and broker are in production mode.
- API cookie hardening, OIDC state signing, issuer+subject identity binding, CSRF origin checks,
  rate limits, body limits, and request timeouts are deployed.
- Postgres app role, statement timeouts, and broker RLS are active.
- API and broker images are published to GHCR and CI/security/image/SBOM workflows are green.
- The core test suite is strong: 24 API tests, 343 Rust tests including Postgres/Anvil/KMS
  integration tests, portal tests, and cross-language receipt parity.
- Offline verification, evidence packs, reviewer links, webhook signing/leases, SSRF defenses,
  and scheduler leader election are implemented.
- TLS is valid; Caddy adds HSTS, frame/referrer/permissions headers, and a report-only CSP.
- Site, docs, app, and verifier are reachable; design selection was removed and only light/dark
  mode remains.

## P0 remediation status (2026-11-13)

| P0 item | Status | Evidence |
|---|---|---|
| SSH hardening | Done with residual root key access | `tessera-deploy` user, key-only password auth, root `prohibit-password`, UFW, fail2ban active; root key remains break-glass |
| Deploy key out of repo | Done locally | `~/.ssh/tessera-vps`; rotate if the key was ever copied |
| Daily backups | Partial — local scheduled, offsite missing | `/usr/local/bin/tessera-backup`, cron 03:15, logrotate, restore drill passed; no offsite/encryption/WAL |
| Monitoring and error tracking | Partial | GitHub uptime workflow and Docker log rotation live; no Prometheus/Alertmanager, Sentry, or status page |
| Image digest pinning | Partial | Live API/broker/portal/verify/site digests pinned; rollback manifest/runbook still incomplete |
| Auth0 cleanup | Partial | M2M and legacy app disabled; deletion, local credential-file removal, custom domain pending |
| Environment key revocation | Done and verified live | Migration 011 stores `broker_key_id`; delete returned 200 and key `revoked_at` was set |
| Redis persistence | Done | AOF + `docker_redisdata`; document RTO/RPO |
| Broker admin bootstrap | Partial | Valid admin key/token live; preflight now checks token equality/key shape; actual broker auth still checked manually |
| Broker RLS | Partial | 9 tables `ENABLE`+`FORCE` RLS; re-applied after migration; no startup assertion or control-plane RLS |
| Domain access copy | Done | Domain allowlist and invited-workspace behavior documented |
| Auth0 RP-initiated logout | Done and verified live | `/auth/logout` returns Auth0 `/v2/logout`; portal redirects; host observed |

## Critical findings (P0)

### 1. Host SSH — largely remediated; root key access remains

Current live findings:

- Non-root `tessera-deploy` user exists with key-only access and limited passwordless sudo.
- `PasswordAuthentication no`; `PermitRootLogin prohibit-password`; UFW allows only 22/tcp,
  80/tcp, 443/tcp, and 443/udp; 22 is rate-limited.
- `fail2ban` is active with the sshd jail; one hostile IP was banned immediately after reboot.
- Root key login still works as break-glass and should be reviewed/removed once console access is
  confirmed.
- OpenSSH and Docker remain directly exposed on a small public VPS; 3,654 failed SSH password
  attempts were observed before password auth was disabled.
- The former repository private key (`new-ssh.txt`) is at `~/.ssh/tessera-vps`; rotate it if it
  was ever shared or copied.

Do next:

- Remove root key login after confirming the provider console break-glass path.
- Rotate the deploy key periodically and remove unused keys.
- Keep the kernel rebooted for OpenSSH/systemd security updates (now `6.8.0-149-generic`).

### 2. Backups are scheduled locally; offsite is still missing

Current live findings:

- `/usr/local/bin/tessera-backup` runs daily at 03:15 via `/etc/cron.d/tessera-backup`.
- The first scheduled dump and evidence archive succeeded at `/var/backups/tessera/`.
- A restore drill into a disposable database restored 11 migrations and one user successfully.
- There is no offsite copy, WAL archive/PITR, encryption-at-rest key, retention policy, or
  backup-failure alert on the live host.
- `BACKUP_OFFSITE_DIR` remains unset; the script supports a local/offsite target when configured.

Do next:

- Configure encrypted offsite retention and alert on backup failure.
- Enable WAL archiving/PITR if the target RPO is below 24 hours.
- Run a clean-host restore drill and record RTO.

### 3. Monitoring is partial: uptime and log rotation only

Current live findings:

- `.github/workflows/uptime.yml` checks site, API health/readiness, and verifier every five
  minutes and opens/closes a GitHub issue; a manual run passed.
- Docker logs rotate at 10 MB with three files per container.
- No Prometheus scrape, Alertmanager, Sentry/error tracker, certificate-expiry monitor, or
  status page is deployed. The API `/metrics` endpoint is still unscraped.
- Disk is 80% used (`1.8 GB` free) after image/build-cache cleanup; capacity is not alerted on.

Do next:

- Add external metrics/alerting and error tracking.
- Alert on `/readyz`, 5xx rate, latency, webhook failures, disk, memory, certificate expiry,
  Postgres connections, Redis errors, and backup failure.
- Add a public status page.

### 4. Auth0 cleanup — M2M disabled; deletion and custom domain pending

Current live findings:

- Auth0 Regular Web Application `Tessera Production` is live with callback, logout URL, web
  origins, authorization-code flow, RS256, and `client_secret_basic`.
- The temporary Management API M2M application and legacy `Tessera` application are disabled,
  but not deleted. M2M credentials still exist at
  `/Users/a/Documents/opencode/tessera-docs/m2m/`.
- The tenant is a `dev-*.us.auth0.com` tenant, not a custom domain.
- RP-initiated logout is implemented: `/auth/logout` returns the Auth0 `/v2/logout` URL and the
  portal redirects. Live verification observed the Auth0 logout host.
- First-admin bootstrap and the `@thetessera.xyz` domain allowlist are documented; existing
  OIDC identities bypass the bootstrap gate.

Do next:

- Delete the unused Auth0 applications and the local credential file; revoke any M2M secret.
- Configure a custom Auth0 domain and email provider for production branding/deliverability.
- Test logout with a full Auth0 SSO session, including `id_token_hint` if required.

### 5. Deployment is digest-pinned live; rollback is still manual

Current live findings:

- Live API/broker/portal/verify/site images are pinned by digest in
  `/opt/tessera/infra/docker/.env`; base Compose uses digest-pinned Postgres/Redis/Caddy images.
- Compose supports `TESSERA_*_IMAGE` overrides and container hardening/logging limits.
- The previous digest and a tested rollback manifest are not recorded; release tags remain
  mutable, and the deploy is still a manual Compose pull/recreate.

Do next:

- Record a deployment manifest with image digests, migration version, and config hash.
- Retain and test the previous digest for rollback.
- Move to immutable release tags/SHA tags for all components.

### 6. Environment deletion revocation — fixed and verified

`broker_key_id` is stored on environments via migration 011. Deleting an environment calls the
broker admin API and revokes the key. Live test: create returned 201, delete returned 200, and
the broker key had `revoked_at` set. A reconciliation job for orphan keys is still absent.

Do next:

- Add a scheduled orphan-key reconciliation/audit.
- Keep testing this path after broker-key changes.

### 7. Redis persistence — enabled; RTO/RPO undocumented

Live Redis now uses AOF (`appendonly yes`) with the `docker_redisdata` volume. Redis holds the
authority-token replay cache, rate-limit windows, and API-key cache; loss still has availability
impact, and single-node RTO/RPO is not documented.

Do next:

- Document the single-node Redis RTO/RPO and fail-closed behavior.
- Back up Redis or move replay prevention to Postgres.

### 8. RLS coverage is partial but active on broker tables

Broker RLS is active and forced on 9 existing tables; `stripe_grants` is absent and the script
skips missing optional tables. The script was re-applied after migration 011; control-plane tables
remain application-enforced only.

Do next:

- Add a startup/deploy assertion for expected RLS tables.
- Add a CI/deploy test that fails if a broker table lacks `ENABLE`/`FORCE ROW LEVEL SECURITY`.
- Add control-plane RLS in a later phase; do not claim it today.

### 9. Broker admin bootstrap is documented, but manual

The API needs a valid broker admin API key plus matching broker admin token to provision
environments. The live deployment now has a valid key for tenant `tessera-admin` and matching
tokens; the earlier 502 was caused by a random non-key value and token mismatch. The runbook
documents this. `infra/scripts/vps-preflight.sh` now checks token equality and API-key shape; it
does not call broker admin authentication.

Do next:

- Add a preflight that calls broker admin authentication before deploy.
- Prefer a dedicated bootstrap command/script over direct SQL.
- Rotate the admin key and remove old bootstrap records on a schedule.

### 10. CSP is report-only

The report-only CSP is useful during rollout, but it does not enforce script/style restrictions.

Do next:

- Remove inline JSON-LD or add hashes.
- Test in staging.
- Switch to enforced CSP with a report endpoint.

## Product and GTM findings

### Strengths

- Clear ICP: AI-native B2B vendors with write/spend agents stuck in enterprise security review.
- Strong wedge: enforce the exact tool call, issue a scoped credential, sign the record, and let
  a reviewer verify it offline.
- Honest evidence labeling (Level 1 broker-observed vs Level 2 caller-reported) is a real
  differentiator in diligence.
- The portal has an unusually broad first version: actions, agents, policies, reviews, evidence,
  transitions, integrations, analytics, audit, and invitations.
- The landing page, verifier, and docs are coherent and avoid unverifiable certification claims.

### Gaps

- No paying customer, design-partner case study, or independent reviewer acceptance.
- Stripe is disabled; pricing exists on paper, but no checkout/subscription flow is live.
- Invitations are manual links; no email delivery or reminder flow.
- Domain-wide access creates a new workspace per user unless they are invited to an existing org;
  this needs explicit product copy.
- No SCIM, custom org SSO, email templates, or organization switching for multiple workspaces.
- Evidence archives are stored on the local evidence volume; no S3/object-storage or retention UI.
- Auth0 logout now uses `/v2/logout`; test the full SSO-session path.
- Provider integrations are not live until real AWS/GitHub/Stripe credentials are configured.
- There is no public status page, support SLA, privacy policy, terms of service, DPA, or
  subprocessor list on the site.
- No analytics or error tracking means product usage and failures are not observable.
- `www.thetessera.xyz` has no DNS record; decide whether to redirect or not.

## Technical findings

### Strong areas

- Rust broker with signed receipts, hash chain, Merkle anchoring, single-use grants, revocation,
  quotas, and provider adapters.
- Explicit authority-token checks: issuer, audience, tenant, agent, expiry, `jti` replay.
- Offline verifier independent of the broker.
- API/broker separation, internal broker network, rate/body/time limits, SSRF controls.
- Postgres app role, statement timeouts, RLS, and backup/restore scripts.
- CI, security, SBOM, image build, `cargo-deny`, dependency review, and digest-pinned base images.

### Remaining engineering risks

- Single VPS, single Postgres, single Redis; no HA or failover.
- Manual SSH deploys; no staging, blue/green, or rollback playbook.
- No load test against the live topology; local benchmarks are not production evidence.
- No cloud KMS/HSM benchmark or production key-custody setup.
- No external pen test or SOC 2 readiness audit.
- No database connection pool alerting or slow-query monitoring.
- No WAF/DDoS protection or edge request filtering.
- No automated secret manager; root-only `.env` plus manual rotation.
- No automatic dependency updates (Renovate/Dependabot) for images and dependencies.
- Evidence/DB volumes are not encrypted by an application-managed key; confirm IONOS disk
  encryption.
- Evidence volume restore into a clean host is not tested; only the database restore drill ran.
- No multi-replica webhook/scheduler/chain test in the live environment.
- No migration rollback strategy; migrations are forward-only and manually triggered on deploy.
- No external certificate-expiry monitor; Caddy renewal is working but unmonitored.
- No CAA/DNSSEC decision; `www` DNS is missing.

## Full action list

### P0 — before inviting a design partner

1. [x] Harden SSH: non-root deploy user, key-only auth, firewall, fail2ban. Residual: root key break-glass.
2. [x] Move the private deploy key out of the repository; rotate if exposed.
3. [~] Schedule local Postgres/evidence backups and verify restore. Missing: encrypted offsite retention, WAL/PITR, failure alert.
4. [~] Add uptime checks and log rotation. Missing: metrics, alerting, error tracking, status page.
5. [~] Pin live images by digest. Missing: retained rollback digest/manifest and immutable release tags.
6. [~] Disable the Auth0 M2M and legacy apps. Missing: deletion, credential-file removal, custom domain.
7. [x] Fix environment deletion to revoke the broker key; verified live.
8. [x] Enable Redis AOF persistence. Missing: documented RTO/RPO.
9. [~] Document broker admin key/token bootstrap; preflight checks token equality/key shape. Missing: live broker-auth call/bootstrap command.
10. [~] Re-apply RLS after migration and verify 9 forced tables. Missing: startup assertion/control-plane RLS.
11. [x] Document domain allowlist vs invited workspace membership.
12. [x] Implement Auth0 RP-initiated logout; verified live.

### P1 implementation status (2026-11-13)

| P1 item | Status | Notes |
|---|---|---|
| Staging environment + rollback | Config/runbook added; live staging blocked | `infra/docker/docker-compose.staging.yml`, `docs/staging-rollback.md`; separate host/Auth0 app still required |
| Evidence object storage | Implemented code; bucket not configured | S3-compatible adapter + local fallback; no production bucket credentials |
| KMS/HSM signing | Bridge exists; production not migrated | `HttpKmsSigner` and runbook; live still uses in-process `BROKER_SIGNING_KEY` |
| Email delivery | Implemented code; provider disabled | Resend adapter for invites/deletion notices; no API key/sender domain live; Auth0 email provider external |
| Stripe/paid messaging | Removed from public site/docs | Billing remains disabled; no checkout or public price list |
| Privacy/terms/DPA/subprocessors/SLA | Published working docs | Counsel review and legal entity details still required |
| Auth0 custom domain/email | Documented; not configured | Requires tenant admin access |
| Tenant export/deletion/retention | Implemented export + 30-day request/cancel + retention setting | Purge is a documented operator workflow; no auto-purge |
| WAF/DDoS/edge limits | Partial | Caddy request-body cap + API rate limits; no managed WAF/DDoS |
| Load tests | Harness added; not run on staging | `scripts/load/authorize.mjs`, docs; staging target required |
| RLS CI/deploy check | Implemented | `infra/scripts/check-rls.sh`; CI step added |
| Control-plane RLS | Design only | `docs/control-plane-rls.md`; not enabled |
| Dependency/image updates | Config added; app not installed | `renovate.json`, `docs/dependency-updates.md` |
| Docs/one-pager/trust | Updated | Legal/security/runbook links added |
| `www` DNS | Documented as intentionally absent | `docs/edge-and-dns.md` |

### P2 implementation status (2026-11-13)

| P2 item | Status | Notes |
|---|---|---|
| SOC 2 readiness | Readiness mapping + evidence cadence added | `docs/soc2-readiness.md`; no auditor, policies, or report yet |
| External penetration test | Scope/rules added; not run | `docs/pentest-scope.md`; independent engagement still required |
| Cloud KMS/HSM benchmark | Harness + matrix added; no real KMS | `scripts/kms-bench.mjs`, `docs/kms-benchmark.md`; live signer still in-process |
| Multi-AZ/managed data + DR | Target design + failover plan added | `docs/multi-az-dr.md`; live remains single VPS |
| SCIM + customer-owned SSO | SCIM Users implemented/tested; SSO design only | `/scim/v2`, org-scoped tokens, Settings UI; SCIM Groups and self-service per-org SSO remain |
| Named support/SLA + incident response | Working docs added | `docs/support-sla.md`, `docs/incident-response.md`; no contractual SLA |
| Case study/reviewer acceptance | Consent/template only | `docs/case-study-template.md`, `docs/reviewer-acceptance.md`; no real acceptance |
| Independent security review | Package/scoping added | `docs/independent-security-review.md`; no engagement |
| Financial model | Transparent calculator/template added | `scripts/finance-model.mjs`, `docs/financial-model.md`; founder must validate inputs |
| Raise/SAFE/team/IP | Founder checklist added | `docs/fundraise-checklist.md`; founder-controlled |

### P1 — design-partner readiness

1. Create a staging environment and a release/rollback runbook.
2. Add object storage for evidence and offsite evidence retention.
3. Move production signing to KMS/HSM or a managed key service.
4. Add email delivery for invites, verification, and operational notices.
5. Configure Stripe billing or remove paid-plan messaging until billing is live.
6. Publish privacy policy, terms, DPA, subprocessor list, and security contact SLAs.
7. Configure an Auth0 custom domain and production email provider.
8. Add tenant deletion, export, retention, and data-deletion workflows.
9. Add WAF/DDoS protection and edge rate limits.
10. Add load tests for two API and two broker replicas, webhook delivery, scheduler, and chain append.
11. Add automatic RLS verification to CI and deploy.
12. Add control-plane RLS design (or keep the current application-enforced limitation explicit).
13. Add dependency/image update automation.
14. Update README, trust center, hardening report, and one-pager to current Auth0/live state.
15. Add `www` DNS or document that it is intentionally unavailable.

### P2 — enterprise and investor diligence

1. SOC 2 Type I readiness and, later, Type II.
2. Scoped external penetration test covering auth, sessions, tenant isolation, SSRF, webhooks,
   proxy, DB roles, and the public verifier.
3. Cloud KMS/HSM benchmark with latency, rotation, and failure tests.
4. Multi-AZ Postgres/Redis or managed equivalents; define RPO/RTO and test failover.
5. SCIM and customer-owned SSO for enterprise.
6. Named support/SLA and incident-response runbook.
7. Customer case study and reviewer acceptance evidence.
8. Independent security review of the receipt, chain, authority, and RLS boundaries.
9. Financial model tied to design partners and paid pilots.
10. Confirm final raise amount, SAFE terms, team slide, and IP/legal ownership.

### P3 — external validation and scale

1. Live Okta/Entra/Auth0 enterprise tenant validation (Auth0 consumer login is now live).
2. Real provider validation with Stripe/AWS/GitHub credentials.
3. Backup/restore and disaster-recovery drill on a clean host.
4. Multi-replica soak test with real traffic and failure injection.
5. Pen-test remediation and re-test.
6. Status page and customer-visible reliability history.

## Claim boundaries

Safe today:

> Tessera is live on a real domain with Auth0 login, a production-configured API/broker,
> signed action records, offline verification, evidence packs, and a working control plane.

Do not claim today:

- SOC 2 certified or compliant
- completed external penetration test
- production HA or enterprise SLA
- cloud KMS/HSM-backed signing
- control-plane RLS
- paying customers or design-partner outcomes
- immutable or tamper-proof storage

## Verification run

- Live `app`, `site`, and `verify` endpoints reachable; `/readyz` healthy after kernel reboot.
- Auth0 login redirect observed; first user/org exists; Auth0 logout URL host observed.
- Environment creation/deletion verified after migration 011: delete returned 200 and broker key
  `revoked_at` was set.
- Local scheduled backup + disposable restore drill passed: 11 migrations and one user restored.
- API tests: 33 passing; Rust: 343 passing; portal: 10 passing; CI/Security/Images/SBOM green on
  `2989db82`; Uptime workflow manual run green; live RLS check 9/9.
- TLS certificate valid until 2027-02-10; kernel `6.8.0-149-generic`; fail2ban active.
- Postgres app role is non-superuser; 9 broker tables have forced RLS.
- Host: ~826 MB RAM, 1 GB swap, 1.8 GB free disk (80%); local daily backups and GitHub uptime
  checks active; Prometheus/Alertmanager/Sentry/status page still absent.
- P1/P2 live: migrations 012–013 applied; org export returned 200 without secrets; legal pages
  served; Caddy request-body cap and `/scim/*` routing reloaded; live SCIM token/list/create/
  delete/revoke passed; S3/email remain unconfigured.
