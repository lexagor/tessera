# Docker deployment

## Local evaluation

```bash
docker compose -f infra/docker/docker-compose.yml up --build
```

- Portal: `http://localhost:8080`
- Verifier: `http://localhost:8080/verify/`
- API: `http://localhost:8080/v1` (same origin as the portal)
- The local stack uses dev auth + broker demo mode. The broker is not exposed publicly.

## Single-VPS production

1. Copy `.env.example` to `.env` and set:
   - `DOMAIN`, `ACME_EMAIL`
   - `AUTH_DEV_MODE=0`, `TESSERA_DEMO_ALLOW=0`, `BROKER_DEMO_ALLOW=0`
   - `PUBLIC_BASE_URL=https://$DOMAIN`, `VERIFY_BASE_URL=https://$DOMAIN`
   - `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`
   - `CONTROL_PLANE_ENC_KEY`, `TENANT_SECRET_ENC_KEY`, `BROKER_SIGNING_KEY`
   - `BROKER_ADMIN_KEY`, `BROKER_ADMIN_TOKEN`
   - Optional: `AGENT_RECEIPT_ED25519_KEY`, `AGENT_RECEIPT_ISSUER_DID`,
     `AGENT_RECEIPT_TSA_URL`
2. Bootstrap the broker admin key once (see `TESSERA_BOOTSTRAP_TENANT` in the broker env).
3. Start with the production overlay:

```bash
docker compose -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.prod.yml up -d --build
```

Caddy obtains TLS automatically for `$DOMAIN`. The broker and internal services have no host
ports; only Caddy is public. Evidence packs are stored in the `evidence` volume by default;
point `EVIDENCE_DIR` at S3-compatible storage in the next phase.

## Operational notes

- `/healthz` is the API liveness probe; add a DB/broker readiness probe before production.
- Keep `pgdata` and `evidence` backed up.
- Rotate `CONTROL_PLANE_ENC_KEY` only with a re-encryption migration; rotating it without one
  makes stored broker keys unreadable.
- Do not run the local dev stack in production: it enables dev auth and broker demo mode.
