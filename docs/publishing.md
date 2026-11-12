# Publishing

How to release the SDKs and verifier. `receipt-schema` is a dependency of `sdk-ts`, `verify`,
`langchain`, and `mcp-adapter`; publish it first (the release workflow does this automatically
on tag). `agent-receipts` remains internal until it is moved under the publishable scope.

## Prerequisites

- An npm org that owns the `@tessera-verify` scope.
- Repository secrets: `NPM_TOKEN` and `PYPI_TOKEN`.
- PyPI project `tessera-verify` configured for trusted publishing or a scoped token.
- Python distribution name: **`tessera-verify`**; import module: **`tessera_verify`**.
- Versions bumped in `packages/*/package.json` and `packages/sdk-py/pyproject.toml`.

## TypeScript / npm

```bash
pnpm install
pnpm typecheck
pnpm --filter @tessera-verify/receipt-schema test && pnpm --filter @tessera-verify/sdk-ts test

# dry run to inspect the tarball contents
pnpm --filter @tessera-verify/receipt-schema publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/sdk-ts publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/verify publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/langchain publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/mcp-adapter publish --dry-run --no-git-checks --access public
```

`pnpm publish` rewrites `workspace:*` dependencies to the published versions, so publish in
this order: `receipt-schema`, `verify`, `sdk-ts`, `langchain`, `mcp-adapter`.

Do not run plain `npm publish` from the workspace package directory; it can publish
`workspace:*` dependencies as-is and make the package uninstallable. If publishing a tarball,
create it with `pnpm pack` first and inspect `package/package.json` before uploading.

### npm 2FA

npm requires either an interactive 2FA code or a granular access token with **Bypass 2FA**
enabled for publishing. If the CLI prompts for an OTP and you do not have an authenticator:

1. Sign in at npmjs.com → Access Tokens → Generate New Token.
2. Choose a granular token with Read and write (publish and stage) access.
3. Enable **Bypass 2FA**.
4. Select the `@tessera-verify` scope / all required packages.
5. Use the token as `NODE_AUTH_TOKEN` for local or CI publishing.

Staged publishing (`npm stage publish`) does not require an OTP at upload time, but a maintainer
must still approve the staged version with 2FA. Do not disable 2FA merely to publish.

## Python / PyPI

PyPI no longer accepts account username/password authentication. Use an API token:

- Username: `__token__`
- Password: the token value (`pypi-…`)

Do not print the token or put it in shell history.

```bash
python -m pip install --upgrade build twine
python -m build packages/sdk-py
twine check packages/sdk-py/dist/*

export TWINE_USERNAME=__token__
read -rs TWINE_PASSWORD
export TWINE_PASSWORD
twine upload \
  packages/sdk-py/dist/tessera_verify-0.1.2-py3-none-any.whl \
  packages/sdk-py/dist/tessera_verify-0.1.2.tar.gz
unset TWINE_PASSWORD
```

The package is published as `tessera-verify`; consumers use `import tessera_verify`.
If a token is ever printed in a terminal transcript, revoke it immediately in PyPI account
settings and create a replacement.

## Automated release

Pushing a `v*` tag runs `.github/workflows/release.yml`:

```bash
git tag v0.1.2 && git push origin v0.1.2
```

It builds npm tarballs and Python distributions, creates a GitHub Release with checksums, stages
`@tessera-verify/receipt-schema`, `@tessera-verify/verify`, `@tessera-verify/sdk-ts`,
`@tessera-verify/langchain`, and `@tessera-verify/mcp-adapter` in the npm staged-publishing queue,
and publishes `tessera-verify` to PyPI when `PYPI_TOKEN` is configured. Publishing steps are
skipped when the corresponding repository secret is absent, so a release can be cut before
external credentials are provisioned. A maintainer must approve the staged npm versions with 2FA:

```bash
npm stage list
npm stage approve <stage-id>
```

The Python SDK is a separate wheel (`tessera-verify`) built from `packages/sdk-py`.

## Checklist

- [ ] Versions bumped consistently (TS + Python + tag).
- [ ] `pnpm typecheck`, `pnpm test`, `cargo test`, `forge test` green.
- [ ] `--dry-run`/`twine check` inspected.
- [ ] Changelog/release notes updated (`CHANGELOG.md`).
- [ ] GitHub Release contains npm tarballs, Python wheel/sdist, verifier CLI, and `SHA256SUMS`.
- [ ] `SECURITY.md` and `LICENSE` present in the package tarball (`files` includes `dist`;
      add `LICENSE`/`README` to `files` if publishing standalone).
