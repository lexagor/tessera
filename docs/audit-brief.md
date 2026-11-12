# Security Audit Brief — Tessera Agent Action Broker

| | |
|---|---|
| **Subject** | Tessera Agent Action Broker (governance & trust plane for autonomous agents) |
| **Version** | 1.0 |
| **Date** | 2026-09-15 |
| **Target commit** | _fill in `git rev-parse HEAD` at submission_ |
| **Primary contact** | security@thetessera.xyz |
| **Repository** | _fill in during intake (public or NDA-gated mirror)_ |

This brief is a complete engagement description. It defines scope, the properties that must
hold, how to build and reproduce, the artifacts provided, expected deliverables, and the
questions we would like the review to answer.

---

## 1. Summary

Tessera authorizes autonomous agents' tool calls, brokers ephemeral credentials so the agent
never holds a provider secret, signs a tamper-evident **receipt** for every decision and
outcome, chains receipts per agent, commits chain roots to an on-chain anchor, and exposes
independent verification plus revocation.

We are seeking a review of the **broker** (Rust) with emphasis on authorization semantics,
credential lifecycle, cryptographic receipt/chain construction, tenant isolation, and the
EIP-1559 anchor transaction path. The system is pre-production; there is no live customer
data, and no production secrets are used during testing.

---

## 2. Scope

**In scope:** `apps/broker` (Rust), ~8.7k LoC across 35 files, plus `contracts/receipts`
(`ReceiptAnchor.sol`, 93 LoC) for cross-checking the on-chain Merkle convention.

**Explicitly out of scope (or optional add-ons, §13):**
- TypeScript SDK and portal (`packages/*`, `apps/portal`) — thin HTTP clients.
- Deployment infrastructure (Docker/Helm) — operational, not code.
- Provider SDK internals (AWS STS, Stripe, GitHub) — trusted but reviewed at the boundary.

---

## 3. System overview

| Component | File(s) | Responsibility |
|---|---|---|
| HTTP surface + auth middleware | `http.rs` (580) | routes, API-key auth, rate/body/time limits |
| Authorize/record/revoke orchestration | `authorize.rs` (564) | policy → credential → receipt → chain; idempotent record |
| Policy engine | `policy.rs` (688) | constraint model + CEL conditions (cached, panic-contained) |
| Receipt signing (EIP-712) | `receipt.rs` (451) | digest, sign, recover, payload hashing, domain |
| Receipt chain | `chain.rs` (422), `chain_pg.rs` (320) | optimistic append, verification, retention, hash partitions |
| Issuers | `issuers/*.rs` (~1.2k) | AWS STS (SigV4), GitHub App (JWT), Stripe (grant), mock |
| Grant proxy | `proxy.rs` (139) | redeem grant, forward one request |
| Signer abstraction | `signer.rs` (208) | local key or KMS/HSM bridge (receipts + anchors) |
| Anchor tx + RPC | `eth.rs` (540) | RLP, EIP-1559 signing, JSON-RPC, confirmation |
| Merkle | `merkle.rs` (233) | sorted-pair tree, proofs, anchor calldata |
| Revocation | `revocation.rs` (158), `revocation_pg.rs` (121) | agent/grant/credential revocation |
| Verification | `verify.rs` (217) | independent receipt/chain/Merkle verification |
| Auth + keys | `auth.rs` (318), `auth_pg.rs` (135) | API keys, tenant resolution, cache decorator |
| Rate limiting / cache | `ratelimit.rs` (167), `cache.rs` (196) | in-memory + Redis backends |
| Telemetry / auto-policy | `telemetry.rs` (387), `telemetry_pg.rs` (217) | argument-shape graph + policy proposal |
| Anchoring store / schedule | `anchoring.rs` (272), `anchoring_pg.rs` (215), `scheduler.rs` (55) | anchor records, per-tenant targets, sweep |
| Canonicalization | `canonical.rs` (111) | cross-language canonical JSON + Keccak-256 |
| Config/bootstrap/metrics | `config.rs`, `bootstrap.rs`, `metrics.rs` | env config, wiring, Prometheus counters |

## 4. Lifecycle (single call)

```
agent ── intent,args ──▶ /v1/authorize
        auth middleware ─▶ tenant (API key)
        revocation check ─▶ policy engine (constraints + CEL)
        allow ─▶ issuer.issue (ephemeral cred or broker-held grant)
        receipt signed (EIP-712) ─▶ appended to per-agent chain
agent ── execute (direct cred, or /v1/proxy for grants)
        grants ─▶ broker observes response ─▶ linked outcome (broker_observed)
        direct ─▶ agent ── result ──▶ /v1/record (agent_reported; idempotent)
operator ─▶ /v1/chain/:agent/anchor/submit (Merkle root → EIP-1559 tx → confirm)
anyone ─▶ /v1/verify/{receipt,chain,merkle} (no trust in broker)
```

## 5. Assets & trust boundaries

- **Assets:** master provider secrets; issued credentials; receipt/chain signing keys; tenant
  policies; the telemetry graph; API keys; on-chain tx fees.
- **Untrusted:** agent runtime, all request bodies.
- **Trusted:** broker process, secret store, signing key (local or KMS).
- **Scoped-trust:** issuers (least-privilege exchange).
- **Trust-minimized:** chain anchor (verification, not secrecy).

## 6. Invariants to verify

1. **Deny-by-default authorization.** A grant matches on resource and enforces every
   constraint and CEL condition; evaluation errors fail closed (unless explicitly `fail_open`).
2. **Credential minimality & binding.** Credentials are tenant-scoped, single-use, and bound
   to `argsHash`; reuse or argument deviation is rejected. Cross-tenant grants/refs rejected.
3. **No secret leakage.** Secrets never enter the agent context or logs; `Debug` for
   credential material and provider configs redacts them.
4. **Receipt integrity.** The EIP-712 digest covers `payloadHash`, `prev`, `agentIdHash`,
   `nonce`; a chain entry is accepted only if `prev` matches the head and the signature
   recovers.
5. **Chain consistency under concurrency.** No forks; optimistic append + conflict retry;
   `pg_advisory_xact_lock` per agent in Postgres.
6. **Tenant isolation.** No cross-tenant read/write of chain, record, anchor, policy, or key.
7. **Resource protection.** Rate limit (429), body cap (413), timeout (408) hold; no
   existence leakage across tenants (404).
8. **Cross-language hashing exactness.** Rust and TypeScript produce identical canonical JSON
   and Keccak-256 payload hashes (shared fixtures).
9. **Revocation effectiveness.** Agent revocation blocks new calls; grant/credential
   revocation reaches the provider where the API exists.
10. **Transaction signing correctness.** EIP-1559 payload/RLP encoding is well-formed and
    recovery yields the configured signer.

## 7. Priority focus areas

1. **Authorization & CEL containment** (`policy.rs`): constraint semantics, the panicking CEL
   parser containment (`catch_unwind`), and whether any input can bypass constraints.
2. **Credential lifecycle** (`issuers/*`, `authorize.rs`, `proxy.rs`): issuance scoping,
   single-use enforcement, tenant binding, revocation, and the proxy's request construction
   (host/path/method handling, SSRF surface).
3. **Receipt & chain cryptography** (`receipt.rs`, `chain.rs`, `verify.rs`): EIP-712 digest
   construction, signature recovery, chain link checks, and the "same signer" rule.
4. **Concurrency** (`chain.rs`, `chain_pg.rs`): fork-freedom under parallel appends.
5. **Auth & tenancy** (`http.rs`, `auth.rs`): key hashing, tenant resolution, cache
   invalidation on revoke, rate-limit bypass.
6. **Anchor tx construction** (`eth.rs`): RLP encoding and EIP-1559 signing; reorg/confirmation
   semantics.
7. **Signer abstraction** (`signer.rs`): local vs KMS path, digest handling, redaction.

## 8. Known limitations (please do not spend budget re-deriving these)

- Rate limiting is per-replica unless `REDIS_URL` is set (Redis fixed-window limiter).
- In-process key is the default signer; KMS/HSM requires an operator-provided bridge.
- Anchor confirmation is best-effort; deep reorg rollback/re-anchor is not implemented.
- Provider-native revocation exists for GitHub installation tokens; Stripe uses broker-grant
  invalidation (no key-delete API); AWS STS cannot be revoked early.
- Postgres uses a single role (no row-level security) — defense-in-depth only.
- A user who bypasses the SDK entirely is out of model for the broker.
- Model providers do not expose weights; provenance is over hashes and signed I/O.

## 9. Build & reproduce

Prerequisites: Rust stable, Node 22 + pnpm (corepack), Foundry, and a local Postgres (and
optionally Redis) for the gated suites.

```bash
# Broker: unit + property + Postgres + anvil + KMS + transport (~140 tests)
cd apps/broker
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test cargo test
REDIS_URL=redis://127.0.0.1:6379 cargo test --test ratelimit_redis   # optional
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Cross-language receipt hashing parity
pnpm --filter @tessera-verify/receipt-schema test

# Contracts
cd contracts/receipts && forge test -vv

# End-to-end (mock Stripe + anvil + broker)
./examples/golden-path/run-local.sh

# Fuzzing (nightly + cargo-fuzz)
cd apps/broker && cargo +nightly fuzz run canonical   # and: cel, merkle, rlp, receipt
```

Expected: broker 140 tests pass; contract suite 5 pass; parity 2 pass. Gated Postgres/anvil/
Redis suites skip cleanly when the services are absent.

## 10. Artifacts provided

- Source repository at the target commit.
- `docs/`: architecture, threat model, receipt spec v1, RFC, this brief, audit-readiness,
  golden-path runbook.
- CycloneDX **SBOM** (generated by `.github/workflows/sbom.yml`).
- **Fuzz harness** with corpus-ready targets (`apps/broker/fuzz`).
- Reproducible test suites and CI definitions (`.github/workflows/`).

## 11. Engagement logistics

- **Review type:** design review + source review + targeted cryptanalysis (receipt/chain,
  EIP-1559 signing). Penetration testing optional (§13).
- **Estimated effort:** ~8–12 reviewer-days for the in-scope broker + anchor contract
  cross-check. We can stage to fit a fixed budget (see §7 priorities).
- **Deliverables we expect:** a findings report with severity, impact, reproduction, and
  remediation guidance; a management summary; and a **retest** of remediated high/critical
  items. See the severity rubric in Appendix C.
- **Access:** repo read; we provide test fixtures and can stand up a sandbox broker with mock
  providers (no real credentials). Details exchanged at intake.
- **Timeline:** prefer a 2-week review window; retest within 1 week of fixes.

## 12. Questions for the auditor

1. Does the EIP-712 digest and chain-link construction preclude receipt forgery or reordering
   without broker state? Any malleability concerns?
2. Can any policy input (constraints or CEL) be bypassed, or cause a panic/DoS despite
   containment?
3. Is the grant model's single-use + `argsHash` binding sufficient, and is the proxy's request
   construction safe against SSRF/host-injection?
4. Is the optimistic chain append genuinely fork-free under the documented concurrency model?
5. Are there gaps in tenant isolation across any endpoint or background job?
6. Is the EIP-1559 transaction construction correct and free of signature/nonce pitfalls?
7. Does the KMS signer abstraction introduce new key-handling risks vs the local signer?

## 13. Optional add-ons

- **Solidity audit** of `ReceiptAnchor.sol` (anchoring correctness, access control).
- **Penetration test** of a deployed sandbox broker (auth, rate limits, proxy).
- **Threat-model workshop** with the maintainer to challenge the documented model.

---

## Appendix A — Component map

See §3. Entry points: `main.rs` (bootstrap + HTTP serve), `bootstrap.rs` (wiring),
`http.rs` (routes). Data stores: in-memory or Postgres (`*_pg.rs`); Redis optional.

## Appendix B — Test inventory

| Suite | Count | Covers |
|---|---|---|
| `cargo test` (unit + property) | ~84 | canonical, policy/CEL, receipt, chain, merkle, eth/RLP, signer, auth, ratelimit, cache, telemetry, anchoring, revocation, verify, issuers |
| `tests/authorize_e2e.rs` | 22 | HTTP authorize/record/chain/anchor/policy/key, isolation, idempotency, concurrency, body limit |
| `tests/auth_e2e.rs` | 8 | API-key auth, revocation, rate limiting |
| `tests/proxy_e2e.rs` | 4 | grant proxy against a mock upstream |
| `tests/issuers_transport.rs` | 3 | AWS SigV4 + GitHub JWT + native revoke |
| `tests/chain_postgres.rs` | 7 | persistence, partitioning, retention, policies, telemetry, revocation, anchoring |
| `tests/parity.rs` + TS parity | 4 | cross-language receipt hashing |
| `tests/kms_signer.rs` | 2 | KMS bridge for receipts + anchors |
| `tests/anchor_eth.rs` | 1 | deploy + anchor + `latestRoot` on anvil |
| `tests/property.rs` | 6 | randomized invariant tests |
| `forge test` | 5 | anchor contract + cross-language root |

## Appendix C — Severity rubric

| Severity | Definition |
|---|---|
| **Critical** | Theft/loss of provider secrets or funds; authorization bypass; receipt forgery; cross-tenant compromise. |
| **High** | Denial of service with low effort; credential over-scoping; chain fork/tamper; tenant data exposure. |
| **Medium** | Limited-impact bypass, information disclosure, or resource-exhaustion requiring specific conditions. |
| **Low** | Hardening/defense-in-depth; best-practice deviations without a demonstrated exploit. |
| **Informational** | Documentation, code quality, or design suggestions. |
