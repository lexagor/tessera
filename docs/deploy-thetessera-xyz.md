# Deploying thetessera.xyz

Production target:

| Host | Service |
|---|---|
| `thetessera.xyz` | landing page + generated docs |
| `app.thetessera.xyz` | tenant portal + control-plane API |
| `verify.thetessera.xyz` | public verifier (`/verify/<token>`) |

## DNS

Create A/AAAA records for the VPS:

```text
thetessera.xyz        A  <vps-ip>
app.thetessera.xyz    A  <vps-ip>
verify.thetessera.xyz A  <vps-ip>
```

Do not point `thetessera.xyz` at a parked page once the VPS is ready; Caddy needs the apex
record for HTTP-01 TLS.

## Environment

On the VPS, set at least:

```bash
SITE_DOMAIN=thetessera.xyz
APP_DOMAIN=app.thetessera.xyz
VERIFY_DOMAIN=verify.thetessera.xyz
ACME_EMAIL=ops@thetessera.xyz

NODE_ENV=production
TESSERA_PRODUCTION=1
AUTH_DEV_MODE=0
COOKIE_SECURE=1
TRUST_PROXY=1
# RATE_LIMIT_AUTH_PER_MINUTE=20
# RATE_LIMIT_PUBLIC_PER_MINUTE=60
# RATE_LIMIT_WRITE_PER_MINUTE=120
TESSERA_DEMO_ALLOW=0
BROKER_DEMO_ALLOW=0
ALLOW_PRIVATE_WEBHOOKS=0

POSTGRES_PASSWORD=...
POSTGRES_APP_PASSWORD=...
# Fresh production volumes create the non-superuser tessera_app role.
DATABASE_URL=postgres://tessera_app:...@postgres:5432/tessera
REDIS_URL=redis://redis:6379

PUBLIC_BASE_URL=https://app.thetessera.xyz
VERIFY_BASE_URL=https://verify.thetessera.xyz
SESSION_COOKIE_NAME=__Host-tessera_session
SESSION_IDLE_HOURS=24
OIDC_ISSUER=https://...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://app.thetessera.xyz/auth/callback
OIDC_LOGOUT_URL=https://YOUR_TENANT.us.auth0.com/v2/logout
OIDC_ALLOWED_DOMAINS=thetessera.xyz
OIDC_STATE_SECRET=...
# Keep automatic email linking off; use invites or an explicit admin bind.
OIDC_ALLOW_EMAIL_LINKING=0

CONTROL_PLANE_ENC_KEY=...
TENANT_SECRET_ENC_KEY=...
BROKER_SIGNING_KEY=...
BROKER_ADMIN_KEY=...
BROKER_ADMIN_TOKEN=...
TESSERA_ADMIN_TOKEN=...
TESSERA_AUTHORITY_HMAC_SECRET=...
TESSERA_AUTHORITY_KID=v1
TESSERA_AUTHORITY_ISSUER=tessera-api
TESSERA_AUTHORITY_AUDIENCE=tessera-broker
# Optional rotation overlap:
# TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS=...
# TESSERA_AUTHORITY_PREVIOUS_KID=v0
# Optional API throttle:
# TESSERA_AUTHORITY_MINT_PER_MINUTE=30

# Optional strict broker egress. When set, every outbound host must be listed and
# DNS resolutions to private/reserved addresses are refused.
# EGRESS_ALLOWLIST=api.stripe.com,api.github.com,sts.us-east-1.amazonaws.com
# Only for local mock upstreams; never enable in production.
# EGRESS_ALLOW_PRIVATE=1
```

Use `openssl rand -hex 32` for the authority, OIDC state, encryption, and signing secrets.
Keep them in the operator secret store, not in git. In production the API refuses to boot
with dev auth, insecure cookies, demo broker mode, private webhooks, missing OIDC config, or
known development secret values.

Domain allowlisting lets a verified `@thetessera.xyz` user sign in. A new domain user creates
their own workspace unless they are invited into an existing organization.

The Postgres init script creates `tessera_app` as `NOSUPERUSER NOBYPASSRLS` on a fresh volume.
Apply the broker RLS policies after the first broker migration, then verify with the RLS test.
RLS is not applied automatically; it is a required post-start step.

`BROKER_ADMIN_KEY` must be a real broker API key, and `BROKER_ADMIN_TOKEN` must equal the
broker's `TESSERA_ADMIN_TOKEN`. A fresh production database has no such key. Bootstrap one
with a temporary `TESSERA_BOOTSTRAP_TENANT` on the broker, set the printed key as
`BROKER_ADMIN_KEY`, then rotate/remove the bootstrap key after the API can provision
environments. The deployment preflight should verify broker admin authentication before
declaring the stack ready.

```bash
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml exec -T postgres \
  psql -U tessera -d tessera -f /sql/rls.sql
```

If the database volume already existed before this role was introduced, create `tessera_app`
manually and update `DATABASE_URL`; do not keep the runtime on the `tessera` superuser role.

## Start

The CI `Images` workflow publishes `ghcr.io/lexagor/tessera-{api,broker,portal,verify,site}:0.1.3`.
Pull those images instead of compiling Rust/Node on a small VPS.

```bash
# GHCR packages must be public or you must authenticate with a read:packages PAT.
# echo "$GHCR_TOKEN" | docker login ghcr.io -u lexagor --password-stdin

docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml pull
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml up -d --no-build
```

Building on the VPS (`up -d --build`) needs substantially more RAM/disk than pulling images;
use it only on a 4 GB+ host or with adequate swap. Do not treat a 2 GB IONOS XS as a build host.

Caddy obtains certificates for all three hosts. The broker and Postgres are not published on
host ports. The API rejects bodies over 2 MB, applies request timeouts, rate-limits auth,
public evidence, and write traffic, and emits structured request logs. Caddy adds HSTS,
frame/referrer/permissions headers, and a report-only CSP. The API exposes Prometheus text at
the internal `/metrics` endpoint; Caddy does not route it publicly.

## OIDC redirect

Add this exact redirect URI to the identity provider:

```text
https://app.thetessera.xyz/auth/callback
```

The API uses `openid-client` discovery, signed state, nonce, PKCE, and code exchange. Users
are bound to `(issuer, subject)`, not just email. Automatic email linking is disabled by
default; use an invite or set `OIDC_ALLOW_EMAIL_LINKING=1` only for a deliberate migration.
Live provider validation is still required for the chosen Okta/Entra/Auth0 tenant.

## VPS preflight

Before changing DNS or starting the stack, confirm the VPS has enough resources and ports:

```bash
free -h
df -h /
docker --version && docker compose version
ss -ltnp | grep -E ':(80|443)\b' || true
dig +short thetessera.xyz A
dig +short app.thetessera.xyz A
dig +short verify.thetessera.xyz A
```

For a 2 GB VPS, add at least 2 GB swap before pulling images; for local builds, use a larger
machine. Open TCP 80/443 in the IONOS firewall/security group. All three DNS names must point to
the VPS before Caddy can complete HTTP-01 certificate issuance.

With the production environment file present, run:

```bash
ENV_FILE=.env VPS_IP=<vps-ip> sh infra/scripts/vps-preflight.sh
```

This checks required variables, broker admin token equality, API-key shape, Docker Compose, free
memory/disk, DNS A records, and port availability without printing secret values. It does not
perform a live broker admin authentication call. After migrations, run
`infra/scripts/check-rls.sh`; it is also run in CI. On an
already-running host, set `TESSERA_SKIP_PORT_CHECK=1` to avoid the expected 80/443 warning.


Optional email and evidence storage settings:

```bash
EMAIL_PROVIDER=resend
EMAIL_API_KEY=...
EMAIL_FROM=Tessera <notifications@thetessera.xyz>
EMAIL_REPLY_TO=partners@thetessera.xyz
EVIDENCE_S3_BUCKET=tessera-evidence
EVIDENCE_S3_REGION=eu-central-1
EVIDENCE_S3_ENDPOINT=            # blank for AWS; set for S3-compatible storage
EVIDENCE_S3_ACCESS_KEY=...
EVIDENCE_S3_SECRET_KEY=...
EVIDENCE_S3_PREFIX=evidence
EVIDENCE_S3_FORCE_PATH_STYLE=0
```

Leave `EMAIL_PROVIDER` empty/disabled to keep the manual invite-link flow. Leave the
`EVIDENCE_S3_*` bucket empty to use the local evidence volume.

## Smoke checks

```bash
curl -fsS https://thetessera.xyz/ | head
curl -fsS https://thetessera.xyz/docs/ | head
curl -fsS https://app.thetessera.xyz/healthz
curl -fsS https://verify.thetessera.xyz/verify/ | head

# Convenience redirects from the marketing domain
curl -sI https://thetessera.xyz/app | grep -i '^location:'
curl -sI https://thetessera.xyz/login | grep -i '^location:'
curl -sI https://thetessera.xyz/verify/ | grep -i '^location:'

# Preview metadata
curl -sI https://thetessera.xyz/og.png | head
```

Then:

1. Sign in through the identity provider.
2. Create an environment.
3. Create an agent key; confirm it shows **owner-bound**.
4. Send one authorize call with the key.
5. Open the action and confirm **Authority method: hmac-jwt**.
6. Create a verification link and open it at `verify.thetessera.xyz`.
7. Run the tamper demo.

## Demo asset

Record the sequence in [`demo-script.md`](demo-script.md) against the deployed stack. Do not
commit a fabricated recording. Save the asset at `docs/assets/tessera-demo.gif` or link a
hosted MP4.
