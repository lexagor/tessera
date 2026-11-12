# Changelog

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
