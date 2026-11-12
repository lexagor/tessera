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
   - `AUTH_DEV_MODE=0`, `TESSERA_DEMO_ALLOW=0`, `BROKER_DEMO_ALLOW=0`
   - `PUBLIC_BASE_URL=https://app.thetessera.xyz`,
     `VERIFY_BASE_URL=https://verify.thetessera.xyz`
   - `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
     `OIDC_REDIRECT_URI=https://app.thetessera.xyz/auth/callback`
   - `CONTROL_PLANE_ENC_KEY`, `TENANT_SECRET_ENC_KEY`, `BROKER_SIGNING_KEY`
   - `BROKER_ADMIN_KEY`, `BROKER_ADMIN_TOKEN`
   - `TESSERA_AUTHORITY_HMAC_SECRET` (at least 32 bytes)
   - Optional rotation window: `TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS` and
     `TESSERA_AUTHORITY_PREVIOUS_KID`; current key id is `TESSERA_AUTHORITY_KID`
   - Optional API throttle: `TESSERA_AUTHORITY_MINT_PER_MINUTE` (default `30`)
   - Optional: `AGENT_RECEIPT_ED25519_KEY`, `AGENT_RECEIPT_ISSUER_DID`,
     `AGENT_RECEIPT_TSA_URL`
2. Bootstrap the broker admin key once (see `TESSERA_BOOTSTRAP_TENANT` in the broker env).
3. Start with the production overlay:

```bash
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml up -d --build
```

Caddy obtains TLS automatically for all three domains and routes:
`$SITE_DOMAIN` → site/docs, `$APP_DOMAIN` → portal + API, `$VERIFY_DOMAIN` → verifier.
The broker and internal services have no host ports; only Caddy is public. Evidence packs are
stored in the `evidence` volume by default; point `EVIDENCE_DIR` at S3-compatible storage in
the next phase.

## Operational notes

- `/healthz` is the API liveness probe; add a DB/broker readiness probe before production.
- Keep `pgdata` and `evidence` backed up.
- Rotate `CONTROL_PLANE_ENC_KEY` only with a re-encryption migration; rotating it without one
  makes stored broker keys unreadable.
- Rotating `TESSERA_AUTHORITY_HMAC_SECRET` invalidates tokens signed by the old key. To overlap,
  set the new secret as `TESSERA_AUTHORITY_HMAC_SECRET`, move the old secret to
  `TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS`, increment `TESSERA_AUTHORITY_KID`, and keep the
  previous secret until the maximum token TTL has elapsed.
- `TESSERA_AUTHORITY_REQUIRE_TOKEN=1` is set in the production overlay. Create agent keys after
  the secret is configured so they are owner-bound; migrate old caller-asserted keys explicitly.
- Do not run the local dev stack in production: it enables dev auth and broker demo mode.
