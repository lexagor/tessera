# Broker Signing-Key Rotation

The broker signs two things with its key: **receipts** (EIP-712, verified by recovery against
the chain id + verifying contract) and **audit artifacts** (export manifests, limits
snapshots, domain-tagged digests). Rotating the key must not invalidate either.

Receipts carry no key id — the signer is recovered from the signature. Verifiers therefore
only need the *set* of addresses the broker has ever used, which is what
`BROKER_SIGNING_KEY_HISTORY` publishes.

## 1. Before you rotate

- Confirm the current address and keep a record of it:

  ```bash
  curl -s https://<broker>/v1/verify/domain | jq '{signer, signers}'
  ```

- Derive the address of a candidate key without exposing it (useful for KMS-held keys):

  ```bash
  tessera-keygen --address 0x<32-byte-hex>   # prints only the address
  ```

- Take a final export with the old key if you want a signed snapshot of the rotation point:

  ```bash
  curl -s -H "x-api-key: $KEY" https://<broker>/v1/export/tenant -o pre-rotation.json
  tessera-verify pre-rotation.json --expect-signer <old-address>
  ```

## 2. Rotate

1. **Generate** (or fetch from your KMS) the new key:

   ```bash
   tessera-keygen            # prints address + private key; store the key in your secret store
   ```

2. **Publish the old address** so pre-rotation receipts stay verifiable:

   ```env
   BROKER_SIGNING_KEY_HISTORY=0x<old-address>[,0x<older-address>…]
   BROKER_SIGNING_KEY=0x<new-private-key>
   ```

   With a KMS bridge, update `KMS_SIGNER_URL`/`KMS_SIGNER_ADDRESS` instead and keep the
   history entry.

3. **Restart** the broker. Startup fails closed if an endpoint is malformed, but a bad key
   hex is rejected by the signer before the listener binds.

4. **Verify** the new state:

   ```bash
   curl -s https://<broker>/v1/verify/domain | jq '{signer, signers}'
   # signer  = the new key
   # signers = [new, old, …]
   ```

## 3. Verify pre-rotation receipts

Receipts and exports signed by the old key continue to verify; pass every accepted address:

```bash
tessera-verify pre-rotation.json \
  --expect-signer 0x<new-address> \
  --expect-signer 0x<old-address>
```

```bash
# Receipt-level check (no broker needed)
curl -s -X POST https://<broker>/v1/verify/receipt \
  -H 'content-type: application/json' \
  -d '{"receipt": {…}, "expectedSigner": "0x<old-address>"}'
```

## 4. After rotation

- Keep old addresses in `BROKER_SIGNING_KEY_HISTORY` for as long as old receipts matter —
  retention (`RETENTION_DAYS`) deletes anchor records and idle chains, not receipts on live
  chains, so this is usually "forever or until the audit window closes".
- Never remove an address from the history while artifacts signed by it still circulate;
  the list is cheap and only ever grows.
- Key material lives only in the secret store / KMS. `tessera-keygen` prints a private key
  exactly once for you to store; it never sends it anywhere and there is no server path that
  echoes keys (exports contain signatures only).

## 5. Emergency rotation (suspected key compromise)

1. Rotate as above, in the same maintenance window.
2. **Revoke affected agents/grants** so no new credentials are issued:
   `POST /v1/revoke` with the affected `agentId`/`grantId` values.
3. Export the full tenant archive (`/v1/export/tenant/archive`) and store it offline — it is
   signed by both keys across the rotation boundary.
4. Treat any receipt signed by the compromised key after the suspected compromise time as
   untrusted; the chain is append-only, so the compromise window is visible as a contiguous
   suffix of each agent's chain.
