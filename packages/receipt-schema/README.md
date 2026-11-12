# @tessera-verify/receipt-schema

Tessera receipt types, canonical JSON, payload hashing, EIP-712 definitions, and JSON Schema
for v1/v2 action records. This package is the shared contract between the Rust broker, the
TypeScript SDK, and external verifiers.

```bash
npm install @tessera-verify/receipt-schema
```

The canonical JSON Schema lives in `schema/receipt-v2.json`. `payloadHash(receipt)` matches the
Rust broker's `receipt::payload_hash_hex`.
