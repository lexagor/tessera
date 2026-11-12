# Distribution checklist

The code is ready to publish; the repository owner must create the external accounts and
run these commands. Do not commit `NPM_TOKEN`, `PYPI_TOKEN`, or any signing key.

## 1. Public repository

```bash
git remote add origin git@github.com:<org>/tessera.git
git push -u origin main
```

Keep the strategy/fundraise/interview docs out of the public tree (see `.gitignore` and
`apps/site/build.mjs`).

## 2. npm packages

The `@tessera` scope must exist in the npm org. Build and dry-run first:

```bash
pnpm install
pnpm --filter @tessera/receipt-schema build
pnpm --filter @tessera/receipt-schema publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/sdk-ts build
pnpm --filter @tessera/sdk-ts publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/verify build
pnpm --filter @tessera/verify publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/mcp-adapter build
pnpm --filter @tessera/mcp-adapter publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/langchain build
pnpm --filter @tessera/langchain publish --dry-run --no-git-checks --access public
pnpm --filter @tessera/agent-receipts build
pnpm --filter @tessera/agent-receipts publish --dry-run --no-git-checks --access public
```

Publish `@tessera/receipt-schema` first. The tag workflow (`.github/workflows/release.yml`)
publishes all packages and the Python SDK when a `v*` tag is pushed.

## 3. Verifier

Deploy `apps/verify` behind TLS (Caddy/Nginx). Set `VERIFY_BASE_URL` in the API to the public
origin so verification links point at it. The verifier is static and does not need a database.

## 4. Agent Receipts export

Set `AGENT_RECEIPT_ED25519_KEY` (32-byte hex seed), `AGENT_RECEIPT_ISSUER_DID`, and optionally
`AGENT_RECEIPT_TSA_URL`. Without the key the export endpoint returns `503`; the native
Tessera receipt remains available.

## 5. Smoke checks

- `curl https://<verifier>/` returns the verification page.
- `npm view @tessera/verify version` matches the release.
- A verification link from the portal resolves at `<verifier>/verify/<token>`.
- The evidence pack and `GET /v1/transitions` show the same authority events.
