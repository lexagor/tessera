# @tessera/agent-receipts

Export a Tessera action record as an Agent Receipts Protocol v0.5.0 W3C Verifiable
Credential. The native EIP-712 receipt remains the broker-signed authoritative record; this
package adds a portable Ed25519-signed envelope for ecosystems that consume Agent Receipts.

```ts
import { exportAgentReceipt } from "@tessera/agent-receipts";

const credential = exportAgentReceipt({
  authorization,
  outcome,
  tenant: "acme",
  issuerDid: "did:web:api.tessera.example",
  signingKey: process.env.AGENT_RECEIPT_ED25519_KEY!,
});
```

`AGENT_RECEIPT_ED25519_KEY` is a 32-byte hex seed. The exporter signs the RFC 8785 canonical
credential without the `proof` field and writes an `Ed25519Signature2020` proof.

For a trusted timestamp, obtain an RFC 3161 token over the canonical credential (without
`proof`) and pass it as `trustedTimestamp`. `requestTrustedTimestamp(tsaUrl, canonical)` builds
the request and returns the base64 DER token:

```ts
import {
  buildAgentReceipt,
  canonicalAgentReceipt,
  requestTrustedTimestamp,
  signAgentReceipt,
} from "@tessera/agent-receipts";

let credential = buildAgentReceipt(input);
const token = await requestTrustedTimestamp(tsaUrl, canonicalAgentReceipt(credential));
credential = buildAgentReceipt({ ...input, trustedTimestamp: token });
credential = signAgentReceipt(credential, signingKey);
```

Exports default to a standalone chain (`sequence: 1`, null previous hash). Pass
`previousReceiptHash` and `sequence` when exporting a receipt that continues a VC chain.
