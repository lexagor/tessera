# Publishing

How to release the SDKs and verifier. `receipt-schema` is a dependency of `sdk-ts` and must
be published first; `langchain` and `mcp-adapter` depend on `sdk-ts` (CI does this automatically
on tag).

## Prerequisites

- An npm org that owns the `@tessera` scope (or rename the scope to one you own).
- Repository secrets: `NPM_TOKEN` and `PYPI_TOKEN`.
- Versions bumped in `packages/*/package.json` and `packages/sdk-py/pyproject.toml`.

## TypeScript / npm

```bash
pnpm install
pnpm typecheck
pnpm --filter @tessera/receipt-schema test && pnpm --filter @tessera/sdk-ts test

# dry run to inspect the tarball contents
pnpm --filter @tessera/receipt-schema publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/sdk-ts publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/verify publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/mcp-adapter publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/langchain publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/agent-receipts publish --dry-run --no-git-checks --access public
```

`pnpm publish` rewrites the `workspace:*` dependency on `@tessera/receipt-schema` to the
published version, so `receipt-schema` must exist at that version before `sdk-ts` is published.

## Python / PyPI

```bash
python -m pip install --upgrade build twine
python -m build packages/sdk-py
twine check packages/sdk-py/dist/*
twine upload packages/sdk-py/dist/*
```

## Automated release

Pushing a `v*` tag runs `.github/workflows/release.yml`:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

It publishes `@tessera/receipt-schema`, `@tessera/sdk-ts`, `@tessera/verify`,
`@tessera/mcp-adapter`, `@tessera/langchain`, and `@tessera/agent-receipts` to npm, and the
Python package to PyPI. A CycloneDX SBOM is produced by `sbom.yml`.

## Checklist

- [ ] Versions bumped consistently (TS + Python + tag).
- [ ] `pnpm typecheck`, `pnpm test`, `cargo test`, `forge test` green.
- [ ] `--dry-run`/`twine check` inspected.
- [ ] Changelog/release notes drafted.
- [ ] `SECURITY.md` and `LICENSE` present in the package tarball (`files` includes `dist`;
      add `LICENSE`/`README` to `files` if publishing standalone).
