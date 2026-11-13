# Dependency and Image Updates

**Last updated:** 2026-11-13

Dependabot is active through [`.github/dependabot.yml`](../.github/dependabot.yml) for npm,
Cargo, GitHub Actions, and Docker. Renovate configuration is also in
[`renovate.json`](../renovate.json) for optional use; installing the Renovate app would add
digest/Helm coverage. Do not run both bots on the same dependency set without grouping. Digest pinning is enabled so base
images and actions are updateable without losing immutability.

## Operating rules

- Group routine patch/minor updates; require approval for majors and runtime/base-image majors.
- Keep GitHub Actions pinned to commit SHAs; Renovate updates the SHA and comment.
- Keep Docker/Compose images pinned to digests; the `TESSERA_*_IMAGE` deployment values remain
  digest-pinned in the host `.env`.
- Update one runtime family at a time (Node, Rust, Postgres, Redis, Caddy) to isolate failures.
- CI must pass Security, SBOM, Images, RLS, and the full test suite before merge.
- After merging an image update, deploy the new digest to staging, run smoke, then production.
- Do not auto-merge majors, Auth0/Stripe SDK majors, or changes that alter auth, signing, RLS,
  or database roles without review.

## Manual fallback

If Renovate is not installed, use Dependabot or a scheduled maintenance PR. The minimum cadence
is weekly for security updates and monthly for routine updates. Record the reviewed digest set
with each release.
