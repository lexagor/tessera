# Staging and Release Rollback Runbook

**Last updated:** 2026-11-13

The production host is a single 2 GB VPS. Do not run a second full stack on it. Use a separate
host (or a short-lived larger machine) for staging, and point it at sandbox providers only.

## Staging topology

- Separate DNS: `staging.thetessera.xyz` (app), `staging-verify.thetessera.xyz`.
- Separate Auth0 application with staging callback/logout URLs.
- Separate Postgres database, Redis namespace/instance, evidence volume, and secrets.
- Never copy production provider credentials, broker signing keys, or customer evidence.
- Mark the environment and UI as staging; use synthetic accounts.

An optional Compose overlay is provided at `infra/docker/docker-compose.staging.yml`. It assumes
an operator-provided `.env.staging` and a host with at least 4 GB RAM. It is not intended for
the production VPS.

```bash
cp infra/docker/.env.staging.example infra/docker/.env.staging
docker compose -p tessera-staging \
  -f infra/docker/docker-compose.yml \
  -f infra/docker/docker-compose.staging.yml \
  --env-file infra/docker/.env.staging up -d --no-build
```

Replace every placeholder; do not reuse production secrets.

## Release process

1. CI green: typecheck, tests, Rust, contracts, Python, RLS check, Security, SBOM, Images.
2. Record the image digests from `ghcr.io/lexagor/tessera-*:sha-<commit>`.
3. Deploy the exact digests to staging with `TESSERA_*_IMAGE=...@sha256:...`.
4. Run migrations and `infra/scripts/check-rls.sh`.
5. Smoke: `/healthz`, `/readyz`, Auth0 login, create/delete environment, evidence pack,
   verification link, webhook delivery, and one offline verification.
6. Deploy the same digests to production with the digest-pinned `.env`.
7. Smoke production, then keep the previous digest set for rollback.

## Rollback

Rollback is an image rollback plus a forward-compatible migration decision:

```bash
ssh root@<host>
cd /opt/tessera/infra/docker
cp .env .env.rollback.$(date -u +%Y%m%dT%H%M%SZ)
# Edit TESSERA_API_IMAGE / TESSERA_PORTAL_IMAGE / ... back to the previous digests.
docker compose pull
docker compose up -d --no-build
curl -fsS https://app.thetessera.xyz/readyz
```

Do not roll back a database migration by dropping columns on a live database. Migrations are
forward-only. If a release is incompatible with the previous API image, keep the new image and
roll forward with a fix. For data corruption, restore the last verified dump into a new
database and cut over only after the restore drill passes.

## Required records

For every production release, record: commit SHA, image digests, migration versions applied,
config hash, deploy time, smoke results, and the previous digest set. Store the record with the
operator runbook, not in the public repository if it contains host details.
