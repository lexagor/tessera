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

AUTH_DEV_MODE=0
TESSERA_DEMO_ALLOW=0
BROKER_DEMO_ALLOW=0

PUBLIC_BASE_URL=https://app.thetessera.xyz
VERIFY_BASE_URL=https://verify.thetessera.xyz
OIDC_ISSUER=https://...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://app.thetessera.xyz/auth/callback
OIDC_ALLOWED_DOMAINS=...

CONTROL_PLANE_ENC_KEY=...
TENANT_SECRET_ENC_KEY=...
BROKER_SIGNING_KEY=...
BROKER_ADMIN_KEY=...
BROKER_ADMIN_TOKEN=...
TESSERA_AUTHORITY_HMAC_SECRET=...
TESSERA_AUTHORITY_KID=v1
TESSERA_AUTHORITY_ISSUER=tessera-api
TESSERA_AUTHORITY_AUDIENCE=tessera-broker
# Optional rotation overlap:
# TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS=...
# TESSERA_AUTHORITY_PREVIOUS_KID=v0
# Optional API throttle:
# TESSERA_AUTHORITY_MINT_PER_MINUTE=30
```

Use `openssl rand -hex 32` for the authority secret and other symmetric secrets. Keep the
secret in the operator secret store, not in git.

## Start

```bash
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml up -d --build
```

Caddy obtains certificates for all three hosts. The broker and Postgres are not published on
host ports.

## OIDC redirect

Add this exact redirect URI to the identity provider:

```text
https://app.thetessera.xyz/auth/callback
```

The API uses `openid-client` discovery, state, nonce, PKCE, and code exchange. Live provider
validation is still required for the chosen Okta/Entra/Auth0 tenant.

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
