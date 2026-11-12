# Distribution checklist

The code is ready to publish; the repository owner must create the external accounts and
run these commands. Do not commit `NPM_TOKEN`, `PYPI_TOKEN`, or any signing key.

Current status:

| Package | Version | Status |
|---|---:|---|
| `@tessera-verify/receipt-schema` | 0.1.3 live | published; 0.1.2 deprecated |
| `@tessera-verify/verify` | 0.1.3 live | published; 0.1.2 deprecated |
| `@tessera-verify/sdk-ts` | 0.1.3 live | published; 0.1.2 deprecated |
| `@tessera-verify/langchain` | 0.1.3 live | published; 0.1.2 deprecated |
| `@tessera-verify/mcp-adapter` | 0.1.3 live | published; 0.1.2 deprecated |
| `tessera-verify` (Python) | 0.1.2 live | published on PyPI |

## 1. Public repository

```bash
git remote add origin git@github.com:<org>/tessera.git
git push -u origin main
```

Keep the strategy/fundraise/interview docs out of the public tree (see `.gitignore` and
`apps/site/build.mjs`).

## 2. npm packages

The `@tessera-verify` scope must exist. `receipt-schema`, `verify`, `sdk-ts`, and `langchain`
are published under it; `mcp-adapter` is the new package in this release. `agent-receipts`
remains internal until renamed. Build and dry-run first:

```bash
pnpm install
pnpm --filter @tessera-verify/receipt-schema build
pnpm --filter @tessera-verify/receipt-schema publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/sdk-ts build
pnpm --filter @tessera-verify/sdk-ts publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/verify build
pnpm --filter @tessera-verify/verify publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/langchain build
pnpm --filter @tessera-verify/langchain publish --dry-run --no-git-checks --access public
pnpm --filter @tessera-verify/mcp-adapter publish --dry-run --no-git-checks --access public
```

Publish in order: `receipt-schema`, `verify`, `sdk-ts`, `langchain`, `mcp-adapter`. The tag workflow
(`.github/workflows/release.yml`) stages them when a `v*` tag is pushed; approve the staged
versions with 2FA from npmjs.com or `npm stage approve <stage-id>`.

## 3. Python / PyPI

The Python distribution is `tessera-verify` (import `tessera_verify`). PyPI requires an API
token with username `__token__`; account passwords are rejected.

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

The tag workflow builds the wheel and publishes it when `PYPI_TOKEN` is configured. Without the
token, the release still builds and attaches the wheel as a GitHub Release artifact.

## 4. Verifier

Follow [`deploy-thetessera-xyz.md`](deploy-thetessera-xyz.md). In short: deploy `apps/site` at
`https://thetessera.xyz`, `apps/portal` + `apps/api` at `https://app.thetessera.xyz`, and
`apps/verify` at `https://verify.thetessera.xyz`. Set `VERIFY_BASE_URL` in the API to the
verifier origin so verification links point at it. The verifier is static and does not need a
database.

## 5. Agent Receipts export

Set `AGENT_RECEIPT_ED25519_KEY` (32-byte hex seed), `AGENT_RECEIPT_ISSUER_DID`, and optionally
`AGENT_RECEIPT_TSA_URL`. Without the key the export endpoint returns `503`; the native
Tessera receipt remains available.

## 6. Smoke checks

- `curl https://verify.thetessera.xyz/verify/` returns the verification page.
- `npm view @tessera-verify/verify version` matches the release.
- A verification link from the portal resolves at `<verifier>/verify/<token>`.
- The evidence pack and `GET /v1/transitions` show the same authority events.
