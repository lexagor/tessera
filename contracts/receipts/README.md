# ReceiptAnchor

Append-only Merkle-root anchoring for Tessera receipt batches.

## Why

Receipts are signed by the tenant and stored off-chain. Anchoring periodic Merkle roots makes the
batch tamper-evident and independently verifiable without publishing payloads.

## Develop

```bash
forge install foundry-rs/forge-std
forge test -vv
```

## Deploy (Base Sepolia first)

```bash
forge create src/ReceiptAnchor.sol:ReceiptAnchor \
  --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PK"
```

Then set `RECEIPT_ANCHOR_ADDRESS` in `.env`.

> Status: scaffold. Access control (per-tenant signing keys) and batch-anchor tooling are TODO.
