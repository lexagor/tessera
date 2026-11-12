# Changelog

## Unreleased

### Security

- Authority tokens now carry and validate `tenant`/`agent_id` scope, enforce `iss`/`aud`,
  require a `jti`, and reject replay through a Redis-or-memory cache.
- Added a `kid` keyring with optional previous-secret overlap for safe HMAC rotation.
- Added a per-user rate limit to `POST /v1/authority-tokens`.

### Site

- Rebuilt the marketing main page in the Vercel-light direction with a proof-card hero,
  security-review narrative, Level 1/2 explanation, design-partner CTA, and verified-action
  link.
- Added `/app`, `/login`, and `/verify` redirects from the marketing domain.
- Added favicon, manifest, OG image, canonical/OG metadata, sitemap, and robots.txt.
- Unified the docs pages on the light Vercel-style surface.

## 0.1.3 — 2026-11-12

### Fixed

- Republished the npm packages from `pnpm pack` tarballs so `workspace:*` dependencies are
  replaced with published versions. npm `0.1.2` packages are deprecated; install `0.1.3` or
  later.
- Documented the npm 2FA / bypass-token publishing path and the workspace-protocol packaging
  pitfall.
- Clarified that PyPI `tessera-verify==0.1.2` remains the current Python release.

## 0.1.2 — 2026-11-12

### Added

- Human authority binding for agent keys: OIDC-authenticated users can bind a key to their
  identity, and the API mints short-lived HS256 delegation tokens for broker verification.
- Explicit per-call authority tokens for agents acting on behalf of multiple end users.
- Delegation status in the portal Agent keys and Action Detail views.
- Release artifacts: npm tarballs, Python wheel/sdist, and SHA256 checksums.
- Vercel AI SDK and PydanticAI examples.
- Concurrency/load benchmark coverage and a cloud benchmark runbook.

### Changed

- Public domain and deployment targets moved to `thetessera.xyz`,
  `app.thetessera.xyz`, and `verify.thetessera.xyz`.
- README/package docs now distinguish published npm/PyPI packages from pending npm packages.
- `tessera-verify==0.1.2` is published on PyPI.
- Release workflow publishes only when the corresponding repository secret is configured;
  GitHub Release artifacts are always built.

### Fixed

- Corrected package version drift between npm and Python.
- Clarified the difference between caller-asserted authority, broker-proxied execution, and
  scoped-credential execution in the portal and verifier.

## 0.1.1 — 2026-11-11

- Published the initial npm verifier/SDK/LangChain packages.
- Added the Python `tessera-verify` source distribution and broker parity methods.
- Added the verifier chain-of-trust view, tamper demo, and local benchmarks.
