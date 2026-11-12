# Golden path

Runs the reference agent end to end through Tessera against real providers and a real chain:
Stripe charge → refund (via the broker-held grant proxy), GitHub installation token → native
revocation, then Merkle anchoring + independent verification.

## One command (fully local)

```bash
./run-local.sh
```

Starts a mock Stripe, anvil with a freshly deployed `ReceiptAnchor`, and the broker, then runs
`golden-path.ts`. No credentials or network access to providers required.

## Against real providers

Set the broker's environment (see `docs/golden-path.md` for the full runbook):

```bash
# Stripe test mode (restricted keys scoped to charges + refunds)
STRIPE_RESTRICTED_KEYS="charges_create=rk_test_...,refunds_create=rk_test_..."

# GitHub App (optional)
GITHUB_APP_ID=... GITHUB_APP_PRIVATE_KEY="$(cat app.pem)"

# Base Sepolia anchoring
CHAIN_ID=84532 RPC_URL=https://sepolia.base.org \
ANCHOR_PK=0x... RECEIPT_ANCHOR_ADDRESS=0x...
```

Then run:

```bash
TESSERA_ENDPOINT=https://your-broker TESSERA_API_KEY=tsk_... \
GOLDEN_GITHUB=1 GOLDEN_GITHUB_INSTALLATION_ID=12345678 \
  pnpm start
```

Skipped steps are reported as `skipped`; failures exit non-zero.

Full runbook: [`docs/golden-path.md`](../../docs/golden-path.md).
