# Internal Security Assessment — 2026-11-13

**Scope:** `thetessera.xyz`, `app.thetessera.xyz`, `verify.thetessera.xyz`, the VPS, public
configuration, and the API/broker control paths. **Not** an external penetration test or SOC 2
audit. Testing was non-destructive; no customer data or production provider credentials were used.

## Verdict for an investor-facing website link

The main site and docs are technically reachable, HTTPS-only, and present a coherent security
posture. For a public **investor deck link**, the main site is acceptable. It is not yet an
enterprise-procurement claim: Auth0 is still on a development tenant, DMARC is `p=none`, there is
no WAF/status page, and backups have no offsite target or production encryption passphrase.

## Findings

### Critical — SSH password authentication was re-enabled

`sshd -T` showed `passwordauthentication yes` despite the hardening file. OpenSSH reads the first
obtained value, and `50-cloud-init.conf` (`PasswordAuthentication yes`) sorted before
`99-tessera-hardening.conf`.

**Fixed:** added `00-tessera-hardening.conf` with key-only auth, `PermitRootLogin
prohibit-password`, and `KbdInteractiveAuthentication no`. `sshd -T` now reports
`passwordauthentication no`; root key login and the deploy key still work; fail2ban is active.

### High — dependency advisories

- **Zod < 4.6.6** memory exhaustion: production API/control plane now uses `zod@4.6.7`; all API
  tests pass. A high advisory remains only in the non-deployed LangChain example because
  `@langchain/core@1.3.7` embeds `zod@3.25.76`. Do not expose that example as a service.
- **Hono** and `@hono/node-server` were updated to 4.13.18 / 2.1.8; middleware/static-path
  advisories no longer apply to the production API.
- **React Router** was updated to 7.18.5; portal tests pass.

### Medium — identity/domain hardening gaps

- Auth0 issuer is `dev-22mt4shyf4w7vo5w.us.auth0.com`; no custom domain. Users see the Auth0
  development host.
- DMARC is `p=none`; SPF is `~all`; a spoofed `partners@`/`security@` message could still be
  delivered. IONOS MX records exist.
- No CAA record and no DNSSEC observed.
- `www.thetessera.xyz` has no A/CNAME. The apex link works; a `www` visitor will not resolve.

### Medium — operational readiness

- No managed WAF/DDoS layer, external metrics receiver, error tracker, or public status page.
- Backups are scheduled locally but not offsite; encryption is supported but
  `BACKUP_ENCRYPTION_PASSPHRASE` and `BACKUP_OFFSITE_DIR` are not configured on the live host.
- Host is a single 2 GB VPS; no Multi-AZ/failover.

### Low / accepted

- `style-src 'self' 'unsafe-inline'` remains because React/Vite uses inline style attributes.
- Missing paths on the portal/site fall back to the SPA with HTTP 200 rather than 404. No secret
  is exposed (e.g. `.env`, `.git`, source-map paths return the app shell), but false 200s are
  confusing and can affect monitoring/SEO.
- `Via: 1.1 Caddy` and `Server: Caddy` are exposed; low value to an attacker.
- The live proof record intentionally exposes an opaque user UUID and tenant slug in signed
  JSON. No email, token, or secret is present.

## Checks that passed

- External ports: only 22, 80, 443; Postgres, Redis, broker, API, and Caddy admin are not
  externally reachable.
- UFW default-deny; fail2ban active with bans; root key-only; password auth disabled after fix.
- TLS 1.2/1.3 only; certificate valid; HTTP→HTTPS 308; HSTS enabled.
- CSP enforced with a matching JSON-LD hash; HSTS, frame-ancestors/XFO, nosniff, referrer,
  permissions, COOP/CORP headers present.
- Unauthenticated `/v1/*`, `/v1/org/export`, `/scim/v2/*` return 401; `/openapi.json` is public
  and contains no secrets; `/metrics` is not publicly reachable.
- CORS preflight from an untrusted origin is rejected; cookie-auth write from an evil Origin is
  403; TRACE is 405.
- Invalid OIDC callback is 400; OIDC state cookie is `__Host-`, HttpOnly, Secure, SameSite=Lax.
- Cross-tenant API test with a second user/org returned empty tenant data and only its own org
  export; control-plane RLS is 19/19 forced.
- Private webhook hosts (`127.0.0.1`, link-local metadata, IPv6 loopback) are rejected.
- Public-verification rate limit returns 429 after the configured budget.
- Static proof page and JSON are live; offline verifier returns `valid: true` with the expected
  signer; proof-link CI passes.
- No live secrets or private keys were found in tracked repository files; source maps are not
  served as maps (the server returns the SPA shell).

## Recommended before an enterprise/security review

1. Auth0 custom domain + production email provider + delete disabled M2M/legacy apps.
2. DMARC `quarantine`/`reject` after validating mail flow; add CAA and DNSSEC.
3. `www` DNS redirect or explicitly publish the apex-only decision.
4. Configure offsite encrypted backups and a restore alert; set the passphrase outside the host.
5. External metrics/Alertmanager/Sentry/status page; WAF/DDoS at the edge.
6. Independent penetration test and remediation/retest.
7. Replace the opaque proof user UUID with a dedicated demo principal if the proof will be
   reused widely.

## Claim boundary

This assessment is internal, non-destructive testing. It is not a completed external penetration
test, SOC 2 opinion, or proof that no vulnerabilities exist.
