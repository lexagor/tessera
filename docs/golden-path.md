# Golden Path Runbook

**Goal:** prove the full loop on real infrastructure — an agent goes through the broker to
real providers and a real chain, and the resulting receipts verify independently.

```
agent → Tessera authorize → broker-held credential
      → Stripe charge + refund (via proxy)            [real Stripe test mode]
      → GitHub installation token + native revoke      [real GitHub App]
      → record outcomes → Merkle anchor → Base Sepolia [real tx]
      → independent verification of the receipt chain
```

The harness lives in `examples/golden-path/`. It is env-driven; it skips any provider you
have not configured and exits non-zero if a configured step fails.

---

## A. Local dry run (no credentials)

```bash
cd examples/golden-path
./run-local.sh
```

Starts a mock Stripe (`mock-stripe.mjs`), anvil with a freshly deployed `ReceiptAnchor`, and
the broker (demo mode, mock-free Stripe issuer pointed at the mock), then runs the harness —
including a real on-chain anchor tx to anvil.

Expected tail:

```
  ok   stripe.charges.create          charge ch_test_…
  ok   stripe.refunds.create          refund re_test_…
  ok   anchor.batch                   4 receipts, root 0x…
  ok   anchor.submit                  tx 0x…
  ok   verify.chain                   4 receipts verified, signer 0x70997970…
  ok   verify.receipt                 recovered 0x70997970… payload 0x…

GOLDEN PATH OK
```

---

## B. Real providers

### B1. Stripe (test mode)

1. In the Stripe **test** dashboard, create two **restricted keys**:
   - `rk_test_…` with **write** on *Charges*
   - `rk_test_…` with **write** on *Refunds*
2. Start the broker with:

   ```bash
   STRIPE_RESTRICTED_KEYS="charges_create=rk_test_CHARGES,refunds_create=rk_test_REFUNDS"
   # Do NOT set STRIPE_API_BASE — defaults to https://api.stripe.com
   ```

The broker selects the narrowest key per resource (`stripe:charges.create` →
`charges_create`) and never hands it to the agent; the agent calls `POST /v1/proxy` and the
broker attaches the key.

### B2. GitHub App (optional)

1. Create a GitHub App with `read` on *Metadata* (enough for `/installation/repositories`).
   Add `write` on *Pull requests*/*Contents* if you also want to open a PR.
2. Install it and note the **installation id**.
3. Broker env:

   ```bash
   GITHUB_APP_ID=123456
   GITHUB_APP_PRIVATE_KEY="$(cat app.pem)"
   ```

4. Harness env: `GOLDEN_GITHUB=1 GOLDEN_GITHUB_INSTALLATION_ID=12345678`.

This mints an installation token, calls the GitHub API to prove it works, then revokes it
**natively** through the broker (`POST /v1/revoke`, `kind: "credential"`).

### B3. Base Sepolia anchoring

1. Deploy the anchor contract:

   ```bash
   cd contracts/receipts
   forge create src/ReceiptAnchor.sol:ReceiptAnchor \
     --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PK" --broadcast
   ```

2. Broker env:

   ```bash
   CHAIN_ID=84532
   RPC_URL=https://sepolia.base.org
   ANCHOR_PK=0x...                 # funded on Base Sepolia
   RECEIPT_ANCHOR_ADDRESS=0x...    # from step 1
   ANCHOR_INTERVAL_SECS=3600       # optional background sweeping
   ```

`POST /v1/chain/:agent/anchor/submit` signs an EIP-1559 tx and submits it; the harness prints
the tx hash (`https://sepolia.basescan.org/tx/0x…`).

---

## C. Broker environment summary

| Env | Purpose |
|---|---|
| `DATABASE_URL` | Postgres (chain, policies, telemetry, revocations, anchors, keys) |
| `REDIS_URL` | optional API-key cache backend |
| `BROKER_SIGNING_KEY` | stable receipt signing key (required outside demo) |
| `TESSERA_DEMO_ALLOW` | `1` accepts `x-tessera-tenant` without a key (demos only) |
| `TESSERA_DEMO_KEY` | plaintext key seeded for tenant `default` in demo mode |
| `TESSERA_ADMIN_TOKEN` | authorizes API-key management |
| `STRIPE_RESTRICTED_KEYS`, `STRIPE_API_BASE` | Stripe proxy |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_API_BASE` | GitHub issuer |
| `CHAIN_ID`, `RPC_URL`, `ANCHOR_PK`, `RECEIPT_ANCHOR_ADDRESS` | on-chain anchoring |
| `ANCHOR_INTERVAL_SECS` | scheduled anchor sweep |

Per-tenant anchoring (multi-chain) is set at runtime:
`PUT /v1/anchor-config {"chainId":8453,"rpcUrl":"…","contract":"0x…"}`.

---

## D. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `expected a broker-held grant for stripe` | `STRIPE_RESTRICTED_KEYS` not set on the broker (so a mock issuer returned a bearer cred) |
| `stripe 401` | restricted key wrong/missing permission for that resource |
| `github API 401/404` | installation id wrong, or App lacks access/permission |
| `anchor.submit … skipped` | `RPC_URL`/`ANCHOR_PK`/`RECEIPT_ANCHOR_ADDRESS` not all set |
| `verify.chain` fails | broker signing key changed between runs (set `BROKER_SIGNING_KEY`) |
| Stripe refund fails | no charge created; set `STRIPE_CHARGE_ID=ch_…` to refund an existing one |

---

## E. What this proves (demo narrative)

- **Least privilege:** the agent never holds a provider secret; it receives a scoped grant
  and the broker attaches the narrowest restricted key on a single-use proxy call.
- **Accountability:** every allow/deny and outcome is a signed receipt chained per agent.
- **Native revocation:** credentials carry a reference; revocation reaches the provider
  (GitHub) or drops the broker-held grant (Stripe).
- **Provable:** the chain and individual receipts verify independently (`/v1/verify/*`);
  the chain root is committed on-chain.
