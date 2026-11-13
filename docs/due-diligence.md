# Tessera — Product & Technical Due Diligence

**Date:** 2026-11-13  
**Repository:** `lexagor/tessera`  
**Code state:** `112f24c7` (working tree also contains pre-existing investor-doc/design changes)  
**Live deployment:** `https://app.thetessera.xyz` on IONOS VPS `198.71.63.45`  
**Method:** source review, live endpoint checks, SSH host inspection, database checks, CI history,
and live Auth0/control-plane validation.

## Verdict

| Question | Answer |
|---|---|
| Is this a credible working demo? | **Yes** |
| Is it ready for a controlled design partner? | **Conditional** — after the P0 operations/security items below |
| Is it ready for public / self-serve production? | **No** |
| Is it enterprise procurement-ready? | **No** — no SOC 2, external pen test, KMS/HSM deployment, HA, or DPA |

The technical core is materially stronger than the operational shell around it. The broker,
receipt, verifier, authority binding, RLS, and test coverage are real. The largest risks are now
host security, backups, observability, deployment reproducibility, and product/GTM proof.

**Current live state:** one user, one org, zero environments after the smoke check; Auth0 login
is live; broker and API are healthy; Postgres runs as `tessera_app` with broker RLS active.

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

## Critical findings (P0)

### 1. Host SSH is the largest current security risk

Live host findings:

- `PermitRootLogin yes`
- `PasswordAuthentication yes`
- `ufw` is inactive
- `fail2ban` is absent
- 3,654 failed SSH password attempts in the last 24 hours
- OpenSSH and Docker are directly exposed on a small public VPS

A private key (`new-ssh.txt`) was also present in the repository working directory. It has been
moved out to `~/.ssh/tessera-vps` and should be treated as a deploy key. Rotate it if it was ever
shared or copied.

Do next:

- Add a non-root deploy user with key-only access.
- Disable root login and password authentication after verifying key access.
- Enable a host firewall allowing only 22, 80, 443 (and 443/udp if HTTP/3 is desired).
- Add fail2ban or equivalent for SSH.
- Keep a break-glass console path before changing SSH.
- Rotate the deploy key periodically and remove unused keys.

### 2. Backups are manual and not scheduled

The backup script exists, but there is no host cron/systemd timer. There is one pre-production
dump at `/root/tessera-pre-prod/`; no daily schedule, offsite copy, WAL archive, or restore drill
on this host.

Do next:

- Schedule daily Postgres dumps and evidence-volume archives.
- Copy both off-host with encryption and retention.
- Enable WAL archiving/PITR if the target RPO is below 24 hours.
- Run a restore drill into a disposable database and record RTO.
- Alert on backup failure.

### 3. No real monitoring or alerting

The API exposes `/metrics`, but no Prometheus scrape, Alertmanager, uptime check, error tracker,
or status page is deployed. Docker json logs are the only telemetry and can fill the 8.7 GB disk.

Do next:

- Scrape API/broker/Caddy/Docker metrics.
- Alert on `/readyz`, 5xx rate, latency, webhook failures, disk, memory, certificate expiry,
  Postgres connections, Redis errors, and backup failure.
- Rotate/limit Docker logs.
- Add Sentry or equivalent for API/portal exceptions.
- Add an external uptime/status page.

### 4. Auth0 cleanup and production tenant polish

- The temporary Management API M2M application is still active; revoke it.
- `/Users/a/Documents/opencode/tessera-docs/m2m/` still contains credentials; delete it.
- The Auth0 tenant is a `dev-*.us.auth0.com` tenant, not a custom domain.
- Logout is local-only; Auth0 SSO session may remain.
- The old `Tessera` Auth0 application remains in addition to `Tessera Production`.

Do next:

- Revoke the M2M app and delete the credential file.
- Delete the unused Auth0 application.
- Configure a custom Auth0 domain and email provider for production branding/deliverability.
- Implement RP-initiated logout with `id_token_hint` or a documented Auth0 logout flow.
- Document the first-admin bootstrap and domain allowlist precisely.

### 5. Deployment is not reproducible by image digest

GHCR publishes `0.1.3` and `latest`, but the Compose deployment references mutable `0.1.3`.
A rebuild overwrites the tag; a rollback cannot reliably identify the exact image that ran.

Do next:

- Publish immutable release tags (`0.1.4`, etc.) and record image digests.
- Deploy by digest (or use immutable SHA tags in Compose).
- Retain the previous image digest for rollback.
- Add a deployment manifest containing image digests, migration version, and config hash.

### 6. Environment deletion leaves broker credentials

`revokeBrokerKey` in `apps/api/src/broker.ts` is currently a no-op. Deleting an environment removes
the control-plane row but does not revoke its broker API key. The key is no longer retrievable,
but it remains valid if it leaked.

Do next:

- Store the broker key id (not only the encrypted key) on the environment.
- Revoke the broker key on delete/rotation.
- Add a reconciliation job for orphan broker keys.
- Audit environment deletion and key revocation.

### 7. Redis has no persistence

Redis holds the authority-token replay cache, rate-limit windows, and API-key cache. A Redis
restart loses replay history and limits; a used authority token could become replayable inside
its TTL after a restart.

Do next:

- Enable AOF (or equivalent) for the replay cache, or move replay prevention to Postgres.
- Back up Redis or make its loss fail closed.
- Document the single-node Redis RTO/RPO.

### 8. RLS coverage is partial and manually applied

Broker RLS is active on existing tables. `stripe_grants` did not exist and was skipped; missing
tables created later will not automatically receive policies. Control-plane tables remain
application-enforced only.

Do next:

- Re-apply the RLS script after every migration that creates broker tables.
- Add a startup assertion for expected RLS tables.
- Add control-plane RLS in a later phase; do not claim it today.
- Add a test that fails if a tenant table lacks `ENABLE`/`FORCE ROW LEVEL SECURITY`.

### 9. Broker admin bootstrap is a hidden operational dependency

The API needs a valid broker admin API key plus `TESSERA_ADMIN_TOKEN` to provision environments.
The live deployment initially had a random non-key value and a token mismatch, causing
environment creation 502s. This is now fixed, but the runbook is incomplete.

Do next:

- Document broker admin key creation and token matching.
- Add a preflight that calls broker admin authentication.
- Prefer a dedicated bootstrap command/script over direct SQL.
- Rotate the admin key and remove the old bootstrap records.

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
- Auth0 logout is local-only, so users may be silently signed back in through Auth0 SSO.
- Provider integrations are not live until real AWS/GitHub/Stripe credentials are configured.
- There is no public status page, support SLA, privacy policy, terms of service, DPA, or
  subprocessor list on the site.
- No analytics or error tracking means product usage and failures are not observable.
- `www.thetessera.xyz` has no DNS record; decide whether to redirect or not.
- README, trust center, one-pager, and hardening report contain stale “live OIDC not yet
  validated” language while Auth0 is now live.

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
- No tested restore of the evidence volume into a clean host.
- No multi-replica webhook/scheduler/chain test in the live environment.
- No migration rollback strategy; migrations are forward-only and manually triggered on deploy.
- No external certificate-expiry monitor; Caddy renewal is working but unmonitored.
- No CAA/DNSSEC decision; `www` DNS is missing.

## Full action list

### P0 — before inviting a design partner

1. Harden SSH: non-root deploy user, key-only auth, firewall, fail2ban, break-glass access.
2. Move the private deploy key out of the repository (done locally; rotate if exposed).
3. Schedule and verify encrypted offsite Postgres/evidence backups.
4. Add external uptime, metrics, alerting, log rotation, and error tracking.
5. Pin deployed images by digest; retain a rollback image.
6. Revoke the Auth0 M2M app and delete its credential file.
7. Fix environment deletion to revoke the broker key.
8. Enable Redis persistence or move replay state to Postgres.
9. Add a deployment preflight that checks broker admin auth and token equality.
10. Re-apply RLS after migrations and assert expected tables.
11. Add explicit product copy for domain access vs invited workspace membership.
12. Implement or document Auth0 RP-initiated logout.

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

- Live `app`, `site`, and `verify` endpoints reachable; `/readyz` healthy.
- Auth0 login redirect observed; first user/org exists.
- Environment creation and deletion exercised successfully after broker-admin-key repair.
- API tests: 24 passing; Rust: 343 passing; CI/Security/Images/SBOM green on `112f24c7`.
- TLS certificate valid until 2027-02-10.
- Postgres app role is non-superuser; broker RLS active.
- Host: ~826 MB RAM, 1 GB swap, 1.7 GB free disk; no scheduled backups or monitoring.
