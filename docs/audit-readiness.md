# Audit Readiness

This document prepares Tessera for a third-party security review. It states scope, the
security invariants a reviewer should test, how to build and reproduce, current coverage,
and known limitations.

> Submission-ready external version: [`audit-brief.md`](audit-brief.md).
> Invariant → code → test map: [`controls-matrix.md`](controls-matrix.md).

## 1. System under review

**In scope:** the Agent Action Broker (`apps/broker`), a Rust service that authorizes agent
tool calls, brokers ephemeral credentials, signs receipts, chains them per agent, anchors
Merkle roots on-chain, and provides revocation + independent verification.

**Out of scope (separate review):**
- TypeScript SDK / dashboard (`packages/*`, `apps/dashboard`) — thin clients.
- Solidity `ReceiptAnchor.sol` — recommend a dedicated contract audit.
- Deployment infra (Docker/Helm) — operational review, not code.

Read first: [`architecture.md`](architecture.md), [`threat-model.md`](threat-model.md),
[`receipt-spec.md`](receipt-spec.md), [`rfcs/0001-action-broker.md`](rfcs/0001-action-broker.md).

## 2. Trust boundaries

- **Untrusted:** agent runtime, request bodies.
- **Trusted:** broker process, secret store, signing keys (local or KMS).
- **Scoped-trust:** provider issuers (least-privilege exchange).
- **Trust-minimized:** the chain anchor (verification, not secrecy).

## 3. Security invariants to verify

1. **Authorization is deny-by-default**; a grant matches on resource and enforces every
   constraint/CEL condition. Fail-closed on evaluation error.
2. **Credentials are tenant-scoped, single-use, and bound to `argsHash`.** Reuse or argument
   deviation is rejected. Grants/credential references for another tenant are rejected.
3. **No secret reaches the agent context or logs.** `Debug` for credential material and
   provider configs redacts secrets.
4. **Receipts are tamper-evident.** A signed digest covers `payloadHash`, `prev`,
   `agentIdHash`, `nonce`; a chain entry is only accepted if its `prev` matches the head.
5. **Chains are per-agent and fork-free** under concurrent appends (optimistic append +
   conflict retry; `pg_advisory_xact_lock` in Postgres).
6. **Cross-tenant reads/writes are impossible** for chain, record, anchor, policies, keys.
7. **Rate/body/time limits hold** (tenant, per-agent, and per-IP budgets; 429, 413, 408)
   without leaking existence.
8. **Cross-language hashing is exact.** Rust and TypeScript produce identical canonical JSON
   and Keccak-256 payload hashes (shared fixtures).
9. **Revocation is effective** for agents (blocks new calls) and grants/credentials
   (provider-native where supported).
10. **Configuration fails closed.** Every operator-configured endpoint is validated at
    startup (scheme, credentials, host); a malformed endpoint aborts boot. With
    `EGRESS_ALLOWLIST` set, outbound calls to other hosts are refused at the proxy and at
    anchor submission.

## 4. How to build and reproduce

```bash
# Rust (unit + property + Postgres-gated + anvil-gated)
cd apps/broker
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Cross-language parity
pnpm --filter @tessera-verify/receipt-schema test

# Contracts
cd contracts/receipts && forge test -vv

# Full loop (mock Stripe + anvil + broker)
./examples/golden-path/run-local.sh
```

Disaster recovery: `tessera-restore <archive-dir> --out <dir>` rebuilds chains from verified
evidence alone, and `POST /v1/import` replays a signed bundle into a live broker idempotently.
Both paths can emit signed attestations (`--attest` / the import response), verifiable with
`tessera-verify --attestation <file>`. Key rotation: see [`rotation.md`](rotation.md). Offline export verification (bundle from the
running broker):

```bash
cargo run --bin tessera-verify -- bundle.json --expect-signer 0x… [--expect-tenant-signer 0x…]
```

Fuzzing harness: `apps/broker/fuzz` (requires `cargo install cargo-fuzz` + nightly).

SBOM: CI job `sbom.yml` emits a CycloneDX SBOM (`tessera-broker.cdx.json`) as an artifact.

## 5. Coverage snapshot

- Rust: 322 tests across unit, integration (HTTP), configuration validation, Postgres,
  transport (mock STS/GitHub), KMS bridge, anvil anchoring, and randomized property tests.
- Cross-language receipt hashing parity: 3 tests (Rust + TS) against shared fixtures
  (receipt payloads and tool-definition hashes).
- Contracts: 5 tests.
- SDK ↔ broker e2e: 1 test (spawns the broker, drives the real TypeScript SDK).
- Golden path: one-command local run; CI covers the broker, SDK end-to-end test, and separate
  tenant-isolation/security jobs. A full compose golden-path smoke is tracked for release hardening.

## 6. Controls added recently (review focus)

v4.7 hardening worth targeted review: tool-definition pinning with drift denial
(`tool_pins.rs`, `/v1/tools`), receipts binding `call.toolHash`, policy-change audit events
(`policy.changed`), and PII/secret redaction in telemetry observations (`telemetry.rs`).

v1.4–v1.5 hardening worth targeted review: tenant-scoped agent chains, RLS, envelope
encryption for tenant secrets, anchor submission claims, SSRF policy on tenant RPC URLs,
optional strict egress allowlist, per-agent rate limits, bounded telemetry cardinality,
outbound timeouts, and constant-time API-key comparison. See `controls-matrix.md` rows
20–121.

## 6. Known limitations (accepted, documented)

- Rate limiting is per-replica unless `REDIS_URL` is set (Redis fixed-window limiter).
- Signing keys may be in-process (`LocalSigner`) or an external KMS/HSM (`KMS_SIGNER_URL`); a
  reference KMS bridge contract is documented but the operator supplies the service.
- Anchor confirmation is best-effort (bounded poll) and tracks block numbers; deep reorg
  handling beyond status re-check is not implemented.
- Provider-native revocation exists for GitHub installation tokens; Stripe uses broker-grant
  invalidation (no delete API); AWS STS cannot be revoked early.
- Multi-tenant isolation is enforced in the broker. Postgres row-level security is available
  via `infra/sql/rls.sql` and covered by the `rls_postgres` test; deploy it when the database
  is shared. Superusers and table owners bypass RLS unless the broker runs as a non-superuser
  role (see `rls.md`).
- No HSM-backed key custody unless the operator provides one via the KMS bridge.

## 7. Suggested auditor focus areas

- EIP-712 digest construction and the receipt chain link/signature checks (`receipt.rs`,
  `chain.rs`, `verify.rs`).
- Authorization evaluation: constraint semantics and CEL containment (`policy.rs`).
- Grant lifecycle: issuance, redemption, single-use, revocation, tenant scoping
  (`issuers/stripe.rs`, `issuers/github.rs`, `authorize.rs`).
- Concurrency: chain append conflict handling (`chain.rs`, `chain_pg.rs`).
- EIP-1559 transaction construction and RLP encoding (`eth.rs`).
- Auth middleware and tenant resolution (`http.rs`, `auth.rs`).

## 8. Contacts

- Security reports: `security@tessera.dev` (see [SECURITY.md](../SECURITY.md)).
- Provide the commit SHA under review; reproducible via the commands above.
