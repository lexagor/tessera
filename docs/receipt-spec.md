# Tessera Receipt Specification (v1 and v2)

Status: draft. This document defines the **Grant Receipt** — the signed, tamper-evident
record of an agent authorization + action — the **v2 action record**, and the **receipt
chain**. V1 records remain verifiable; new deployments should emit v2.

## 1. Receipt

A receipt is canonical JSON (object keys sorted, no insignificant whitespace). Field names
are camelCase.

```jsonc
{
  "v": 1,
  "tenant": "acme",
  "agent": "billing-agent",
  "user": "user_42",
  "intentHash": "0x…",              // keccak256(intent string)
  "authorization": {
    "decision": "allow",            // "allow" | "deny"
    "policy": "acme-refunds",
    "policyVersion": 7,
    "resource": "stripe:refunds.create",
    "anomalyScore": 0.0
  },
  "call": {
    "tool": "stripe.refunds.create",
    "argsHash": "0x…",              // keccak256(canonical JSON of args)
    "resultHash": "0x…",            // set when the outcome is recorded; null otherwise
    "toolHash": "0x…"               // approved tool-definition hash; omitted when the tool is not pinned
  },
  "grant": {
    "provider": "stripe",
    "ttlS": 30,
    "singleUse": true,
    "status": "issued"              // "issued" | "used" | "denied" | "expired" | "revoked"
  },
  "ts": "2026-09-15T12:00:00Z",     // RFC 3339, UTC, seconds precision
  "nonce": "0x…",                   // 32 random bytes
  "prev": "0x…" | null,             // payloadHash of the previous receipt in the chain
  "signature": "0x…" | null         // 65-byte secp256k1 signature (r ‖ s ‖ v), v ∈ {27,28}
}
```

The canonical JSON Schema is `packages/receipt-schema/schema/receipt-v1.json` (ECMA-424 /
CycloneDX-compatible tooling can consume it as a BOM-adjacent schema).

`toolHash` binds the receipt to the tool *definition* (name, description, input/output
schema, annotations) the caller presented at authorization time. When the tenant has
pinned that tool, the broker refuses the call unless the presented hash matches the
approved pin, and records the hash in the receipt. Unpinned tools omit the field, so
receipts and payload hashes produced before pinning was introduced remain valid.

## 2. Hashing

- `canonicalize(value)` — recursively sort object keys, no whitespace (implemented in both
  Rust `canonical.rs` and TypeScript `receipt-schema`).
- `payloadHash = keccak256(canonicalize(receipt without "signature"))`.

## 3. Signature (EIP-712)

Digest:

```
domainSeparator = keccak256(abi.encode(
  keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
  keccak256("TesseraReceipt"), keccak256("1"), chainId, verifyingContract))

structHash = keccak256(abi.encode(
  keccak256("Receipt(bytes32 payloadHash,bytes32 prev,bytes32 agentIdHash,bytes32 nonce)"),
  payloadHash, prev, keccak256(agent), nonce))

digest = keccak256("\x19\x01" ‖ domainSeparator ‖ structHash)
```

`signature = secp256k1_sign(digest)` with recovery id, serialized as `r(32) ‖ s(32) ‖ v(1)`,
`v = recoveryId + 27`. `prev` is the zero word when null. Signatures must be low-S; the
verifier rejects high-S (malleable) signatures.

## 4. Receipt chain

Per agent, receipts form an append-only chain: each receipt's `prev` is the previous
receipt's `payloadHash`. Verification recovers the signer from every receipt (no key
required) and requires:

1. every `prev` link matches the previous entry's `payloadHash`;
2. every entry's stored `payloadHash` recomputes from its receipt;
3. all receipts recover to **one** signer address.

When the broker has a configured signing key it also pins the recovered address.

## 5. Merkle anchoring

A batch of receipt `payloadHash` leaves is folded into a Merkle tree with sorted-pair
hashing: `node = keccak(min(a,b) ‖ max(a,b))`; an odd node is carried up unchanged. The root
and `(tenant, root, count)` are submitted to `ReceiptAnchor.anchor(bytes32,bytes32,uint64)`
(selector `0x15954b2c`), giving an on-chain, append-only commitment to the batch.

## 6. Verification

Independent verification needs only the EIP-712 domain (`chainId`, `verifyingContract`) and
the receipt bytes. Public endpoints:

- `POST /v1/verify/receipt` — recover the signer, optionally compare to `expectedSigner`.
- `POST /v1/verify/chain` — verify links, hashes, and a consistent signer.
- `POST /v1/verify/merkle` — verify a leaf against a root with an inclusion proof.
- `GET /v1/verify/domain` — the broker's domain + signer address.

## 7. Receipt v2 (action records)

V2 keeps the v1 envelope and adds the binding fields a third-party reviewer needs. It uses
**two linked records**, because the authorization decision must be signed before execution
and the outcome can only be signed after it:

- `AuthorizationRecordV2` — emitted by `/v1/authorize`; binds the principal, agent metadata,
  intent, policy content, tool definition, arguments, and credential.
- `OutcomeRecordV2` — emitted by `/v1/record` or by the broker after a proxied call;
  carries the same `actionId`, links to the authorization via `authorizationReceiptId`
  (and to the chain via `prev`), and adds `outcome`.

Additional v2 fields (camelCase):

```jsonc
{
  "v": 2,
  "actionId": "uuid",
  "principal": {
    "principalId": "user_42",
    "principalType": "user",
    "authorityRef": "oauth_grant_9f2",
    "authorityHash": "0x…",          // keccak256 of the authority artifact; no raw consent stored
    "verifiedAt": "2026-11-06T12:00:00Z",
    "verificationMethod": "oidc"
  },
  "agentMeta": {
    "agentId": "billing-agent",
    "agentVersion": "1.2.0",
    "modelId": "gpt-5",
    "operatorId": "acme",
    "environment": "production"
  },
  "intent": {
    "intentHash": "0x…",
    "requestedScopes": ["refunds.create"],
    "riskClass": "money-movement",
    "declaredPurpose": "refund a duplicate charge"
  },
  "policy": {
    "policyId": "acme-refunds",
    "policyVersion": 7,
    "policyHash": "0x…",             // canonical hash of the complete policy document
    "decision": "allow",
    "reasonCode": "grant matched",
    "evaluatedInputsHash": "0x…",
    "evaluatorVersion": "tessera-policy-v1"
  },
  "credential": {
    "issuer": "stripe",
    "credentialType": "broker_grant",
    "thumbprint": "0x…",             // non-secret fingerprint of the issued credential
    "scopes": ["refunds.create"],
    "ttlSeconds": 30,
    "singleUse": true,
    "issuanceId": "grant_…"
  },
  "authorizationReceiptId": "0x…",  // payloadHash of the authorization record
  "outcome": {
    "status": "success",             // success | failure | denied | timeout | unknown
    "source": "broker_observed",     // broker_observed | agent_reported
    "resultHash": "0x…",
    "errorClass": "ProviderError",
    "externalRef": "re_123",
    "completedAt": "2026-11-06T12:00:05Z"
  },
  "attestation": {
    "signerKeyId": "0x…",
    "signatureAlg": "secp256k1-eip712",
    "timestamp": "2026-11-06T12:00:00Z",
    "transparencyLogIndex": null,
    "anchorRef": null
  }
}
```

`outcome.source` distinguishes an outcome the broker observed while forwarding a grant
(`broker_observed`) from one the agent supplied through `/v1/record` (`agent_reported`).
Only broker-held grants can be observed directly; AWS/GitHub bearer credentials remain
caller-reported.

`credential.thumbprint` is a non-secret fingerprint over the issuer, resource, TTL, argument
hash, and a non-secret issuance id. The broker never derives receipt fields from a bearer
secret; opaque tokens fall back to a random issuance id.

### V2 verification

`receipt::validate_v2` (Rust) and `validateReceipt` (`@tessera/receipt-schema`) require
`actionId`, `principal`, `agentMeta`, `policy`, and `attestation`; an allowed record must also
carry `credential`. In v2, `user` mirrors `principal.principalId`. The verifier checks the hash
formats, the signature, and the chain link.

Outcomes may arrive after a later authorization for the same agent. Such an outcome carries
`authorizationReceiptId` and uses the current chain head as `prev`; verifiers accept either
that durable link or the older immediate `prev` link. This keeps concurrent tool calls
recordable without breaking the linear chain.

**Authority verification is a deployment concern.** The broker binds the authority artifact the
caller presents and records the `verificationMethod`.

- With `TESSERA_AUTHORITY_HMAC_SECRET` configured, the broker verifies an HS256
  `authorityToken` JWT minted by the tenant backend, requires `sub`/`exp`, rejects tokens with
  an expiry beyond 24 hours or an `iat` in the future, and records
  `verificationMethod: "hmac-jwt"`. `TESSERA_AUTHORITY_REQUIRE_TOKEN=1` rejects calls without a
  token. The token's `sub`, `jti`/`authority_ref`, and `principal_type` override the
  caller-asserted principal. Mint these tokens short-lived (minutes) in the tenant backend;
  the broker caps the accepted expiry at 24 hours.
- Without a configured secret, the method is `user_id` (a caller-asserted binding); the receipt
  proves what the broker recorded, not that an IdP authenticated it. Do not claim IdP
  verification unless the deployment actually performs it.

### V2 domain version

V2 records use EIP-712 domain version `"2"` with the same typehash and payload-hash
construction. V1 verifiers therefore recover a different signer for v2 and cannot silently
accept the new schema. The public verifier supports both versions and selects by `v`.

### V2 policy history

`policy.policyHash` commits to the complete policy document at decision time. The broker keeps
an append-only `policy_versions` history and the tenant evidence archive includes
`policies.json` (content hash + document), so an old receipt remains checkable after a policy
edit. Policy versions are immutable: changing a policy document requires incrementing its
`version`; the broker rejects a same-version content change. V2 records also carry `authorization.policyHash` for consumers that read only the
v1-shaped authorization block.

## 8. Versioning

The `v` field is the receipt schema version. Backward-incompatible changes bump `v`; the
JSON Schema files (`receipt-v1.json`, `receipt-v2.json`) and this document are updated
together. Anchoring commits to `payloadHash`, so any change to the canonical form or EIP-712
types creates a new digest space.

## Evidence manifest field naming

Manifest and bundle fields are **snake_case** (`receipt_count`, `from_index`, `prev_before`,
`next_from`) and are frozen: the manifest digest signs the canonical JSON of exactly these
fields, so renaming would invalidate every previously written bundle and archive. HTTP request
and response payloads elsewhere follow camelCase; the evidence artifacts are the deliberate
exception and must be parsed as-is.

### Paged exports

`GET /v1/export/chain/:agent?from=<index>&limit=<n>` returns a deterministic page:
`from_index` is the first chain index included, `prev_before` is the payload hash of the
receipt that precedes the page (absent on a genesis page), and `next_from` points at the next
page when more receipts follow. Each page verifies independently (`ExportBundle::verify`) and
`prev_before` chains it to its predecessor, so an auditor can reconstruct a long chain page by
page without trusting ordering.

## 8. Portability and standards

Tessera's native record remains the EIP-712/secp256k1 receipt. For consumers of the Agent
Receipts Protocol, `@tessera/agent-receipts` exports the same action as an Agent Receipts
v0.5.0 W3C Verifiable Credential with an Ed25519 proof. The export includes an optional
RFC 3161 `trusted_timestamp`; `requestTrustedTimestamp` builds the RFC 3161 request and returns
the base64 DER token. The native signature is the trust anchor; the VC is a portability
envelope.

Authority changes are not mutated into historical receipts. They are appended to the signed
key-event ledger as `authority.*` transitions (see
[`authority-transitions.md`](authority-transitions.md)).
