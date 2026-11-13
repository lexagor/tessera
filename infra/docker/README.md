# Docker deployment

## Local evaluation

```bash
docker compose -f infra/docker/docker-compose.yml up --build
```

- Portal: `http://localhost:8080`
- Verifier: `http://localhost:8080/verify/`
- Site + docs: `http://localhost:8081/`
- API: `http://localhost:8080/v1` (same origin as the portal)
- The local stack uses dev auth + broker demo mode. The broker is not exposed publicly.

## Single-VPS production

1. Set these environment variables (or put them in an operator-managed `.env`):
   - `SITE_DOMAIN=thetessera.xyz`, `APP_DOMAIN=app.thetessera.xyz`,
     `VERIFY_DOMAIN=verify.thetessera.xyz`, `ACME_EMAIL`
   - `NODE_ENV=production`, `TESSERA_PRODUCTION=1`, `AUTH_DEV_MODE=0`,
     `COOKIE_SECURE=1`, `TESSERA_DEMO_ALLOW=0`, `BROKER_DEMO_ALLOW=0`
   - `POSTGRES_PASSWORD`, `POSTGRES_APP_PASSWORD`,
     `DATABASE_URL=postgres://tessera_app:...@postgres:5432/tessera`,
     `REDIS_URL=redis://redis:6379`
   - `PUBLIC_BASE_URL=https://app.thetessera.xyz`,
     `VERIFY_BASE_URL=https://verify.thetessera.xyz`
   - `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
     `OIDC_REDIRECT_URI=https://app.thetessera.xyz/auth/callback`,
     `OIDC_STATE_SECRET`
   - `CONTROL_PLANE_ENC_KEY`, `TENANT_SECRET_ENC_KEY`, `BROKER_SIGNING_KEY`
   - `BROKER_ADMIN_KEY`, `BROKER_ADMIN_TOKEN`, `TESSERA_ADMIN_TOKEN`
   - `TESSERA_AUTHORITY_HMAC_SECRET` (at least 32 bytes)
   - Optional rotation window: `TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS` and
     `TESSERA_AUTHORITY_PREVIOUS_KID`; current key id is `TESSERA_AUTHORITY_KID`
   - Optional API throttle: `TESSERA_AUTHORITY_MINT_PER_MINUTE` (default `30`)
   - Optional: `AGENT_RECEIPT_ED25519_KEY`, `AGENT_RECEIPT_ISSUER_DID`,
     `AGENT_RECEIPT_TSA_URL`
2. Bootstrap the broker admin key once (see `TESSERA_BOOTSTRAP_TENANT` in the broker env).
3. Pull the published images and start without rebuilding on the VPS:

```bash
# Make GHCR packages public or authenticate with a read:packages PAT.
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml pull
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml up -d --no-build
```

`up --build` is only appropriate on a larger host/with swap; do not compile Rust on a 2 GB VPS.
Run `ENV_FILE=.env VPS_IP=<vps-ip> sh infra/scripts/vps-preflight.sh` before changing DNS;
on a live host add `TESSERA_SKIP_PORT_CHECK=1`.

Caddy obtains TLS automatically for all three domains and routes:
`$SITE_DOMAIN` → site/docs, `$APP_DOMAIN` → portal + API, `$VERIFY_DOMAIN` → verifier.
The marketing domain redirects `/app` and `/login` to the portal, and `/verify` to the
verifier. The broker and internal services have no host ports; only Caddy is public. Evidence packs are
stored in the `evidence` volume by default; point `EVIDENCE_DIR` at S3-compatible storage in
the next phase.

## Operational notes

- `/healthz` is the API liveness probe; `/readyz` checks Postgres and the broker.
- The API exposes internal Prometheus text at `/metrics`; Caddy does not route it publicly.
- Starter Prometheus alert rules are in `infra/observability/alerts.yml`.
- With `REDIS_URL`, the broker scheduler elects one leader across replicas. Without Redis,
  run a single broker replica or accept duplicate scheduled work.
- Production must run as the non-superuser `tessera_app` role. The init script creates it on a
  fresh Postgres volume; apply `infra/sql/rls.sql` after the first broker migration.
- Keep `pgdata` and `evidence` backed up. `infra/scripts/backup.sh` writes a custom-format
  Postgres dump and an evidence archive; `infra/scripts/restore-postgres.sh` restores a dump.
  Restore evidence by extracting its archive into the configured evidence directory.
- Rotate `CONTROL_PLANE_ENC_KEY` only with a re-encryption migration; rotating it without one
  makes stored broker keys unreadable.
- Rotating `TESSERA_AUTHORITY_HMAC_SECRET` invalidates tokens signed by the old key. To overlap,
  set the new secret as `TESSERA_AUTHORITY_HMAC_SECRET`, move the old secret to
  `TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS`, increment `TESSERA_AUTHORITY_KID`, and keep the
  previous secret until the maximum token TTL has elapsed.
- `TESSERA_AUTHORITY_REQUIRE_TOKEN=1` is set in the production overlay. Create agent keys after
  the secret is configured so they are owner-bound; migrate old caller-asserted keys explicitly.
- Do not run the local dev stack in production: it enables dev auth and broker demo mode.
