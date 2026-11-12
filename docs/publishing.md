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

## Python / PyPI

```bash
python -m pip install --upgrade build twine
python -m build packages/sdk-py
twine check packages/sdk-py/dist/*
twine upload packages/sdk-py/dist/*
```

The package is published as `tessera-verify`; consumers use `import tessera_verify`.

## Automated release

Pushing a `v*` tag runs `.github/workflows/release.yml`:

```bash
git tag v0.1.1 && git push origin v0.1.1
```

It stages `@tessera-verify/receipt-schema`, `@tessera-verify/verify`,
`@tessera-verify/sdk-ts`, `@tessera-verify/langchain`, and `@tessera-verify/mcp-adapter` in the
npm staged-publishing queue, and publishes `tessera-verify` to PyPI.
A maintainer must approve the staged versions with 2FA:

```bash
npm stage list
npm stage approve <stage-id>
```

The Python SDK is a separate wheel (`tessera-verify`) built from `packages/sdk-py`.

## Checklist

- [ ] Versions bumped consistently (TS + Python + tag).
- [ ] `pnpm typecheck`, `pnpm test`, `cargo test`, `forge test` green.
- [ ] `--dry-run`/`twine check` inspected.
- [ ] Changelog/release notes drafted.
- [ ] `SECURITY.md` and `LICENSE` present in the package tarball (`files` includes `dist`;
      add `LICENSE`/`README` to `files` if publishing standalone).
