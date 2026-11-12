# RFC 0001 — Agent Action Broker

> **Historical spec (updated November 2026).** The broker ships receipt v2 and is now sold as
> the proof layer for agent actions. See [`receipt-spec.md`](../receipt-spec.md) and
> [`proof-of-action.md`](../proof-of-action.md).

- Status: Draft
- Author: Tessera
- Created: 2026-09-15
- Codename: Tessera
- Implementation: **v2 (action records)** — receipt v2 binds the principal authority, policy
  hash, tool definition, credential thumbprint, and outcome; tenant-scoped chains with
  storage-level link uniqueness, idempotent outcomes, proxy method allowlist + 1 MiB response
  cap, and per-IP public-route limits. 322 Rust test functions, plus Solidity,
  SDK e2e, and cross-language hashing-parity tests.

## Summary

The Agent Action Broker is the launch wedge of the Tessera governance plane. It sits between an
autonomous agent and any privileged resource (cloud API, SaaS, database, MCP tool) and issues
**ephemeral, intent-validated, single-use credentials** per tool call. Every authorization decision
and outcome is recorded as a cryptographically signed **receipt**.

## Motivation

Agents are being given static, highly privileged, long-lived credentials. This is:
- a catastrophic exfiltration vector (a single prompt injection can leak the key),
- unauditable (logs are self-asserted),
- impossible to scope to a specific intent.

The broker replaces the static key with a *capability* that lives for one call and is bound to the
declared intent and arguments.

## Goals

- One-line SDK adoption (`wrap(client)`), with a silent-proxy fallback.
- Sub-10ms authorization + issuance on the hot path.
- Single-use credential bound to `args_hash`, TTL default 30s.
- Tamper-evident receipt for every decision + outcome.
- Cross-SaaS instant revocation.
- Emit the graph edges that power auto-policy generation.

## Non-goals (this RFC)

- Full execution sandboxing (microVM) — later layer.
- Kernel/eBPF enforcement — later layer.
- Full AI-BOM — later layer.
- Certifications (SOC 2, ISO) — later readiness work.

## Request lifecycle

```
agent code
  └─ sdk.wrap(client).call(tool, args)
       └─ broker.Authorize(declared_intent, tool, args, agent_id, user_id)
            ├─ policy eval (CEL): intent scope ∧ user RBAC ∧ resource allowlist ∧ anomaly score
            ├─ issuer.Exchange(provider, scoped_request)   # AWS STS / GH App / Stripe / OAuth2
            ├─ mint ephemeral credential (TTL 30s, single-use, bound to args_hash)
            └─ sign GrantReceipt (EIP-712)
       └─ client executes with the ephemeral credential
       └─ broker.Record(outcome, result_hash)   # append to graph + receipt chain
       └─ revoke / expire
```

## Components

| Component | Tech | Responsibility |
|---|---|---|
| `apps/broker` | Rust (axum) | authorize + issue; hot path; holds only TTL-scoped material |
| `apps/api` | TS (Hono) + Prisma | control plane: CRUD, tenancy, policy versions, dashboards API |
| `apps/portal` | Vite + React | product console: actions, agents, policies, evidence, reviews |
| `packages/core-policy` | TS + CEL | shared policy model & evaluation helpers |
| `packages/issuers` | TS adapters | AWS STS, GCP STS, GitHub App, Stripe restricted keys, OAuth2 token exchange |
| `packages/receipt-schema` | TS + JSON Schema | receipt schema, EIP-712 types, hashing |
| `packages/sdk-ts` / `sdk-py` | TS / Python | drop-in wrappers |
| `packages/mcp-adapter` | TS | MCP stdio/SSE middleware |
| `contracts/receipts` | Solidity (Foundry) | Merkle anchor for receipt batches |
| secret-store | libsodium/age → KMS/HSM | master secrets; never exposed to agent runtime |

## Data model (core tables)

- `tenants`, `users`, `agents` (identity, owner, delegation chain)
- `policies`, `policy_versions` (CEL source, scope, resource allowlist)
- `intents` (declared intent, source, confidence)
- `authorizations` (decision, matched policy, anomaly score, latency)
- `grants` (credential reference, provider, TTL, args_hash, status)
- `tool_calls` (tool, args_hash, result_hash, duration, status)
- `resources` (provider, urn, sensitivity)
- `receipts` (seq, prev_hash, payload_hash, signature, merkle_batch)
- `anomalies`, `integrations`, `audit_log`

## Receipt schema (draft)

```jsonc
{
  "v": 1,
  "tenant": "did:tessera:...",
  "agent": "did:tessera:agent:...",
  "user": "did:tessera:user:...",          // on whose behalf
  "intent": { "hash": "0x...", "ref": "intent_id" },
  "authorization": {
    "decision": "allow",
    "policy": "pol_...",
    "policy_version": 7,
    "resource": "stripe:charge",
    "anomaly_score": 0.03
  },
  "call": { "tool": "stripe.charges.create", "args_hash": "0x...", "result_hash": "0x..." },
  "grant": { "provider": "stripe", "ttl_s": 30, "single_use": true, "status": "used" },
  "ts": "2026-09-15T12:00:00Z",
  "nonce": "0x...",
  "prev": "0x..."                           // receipt chain link
}
```

Signature: EIP-712 over the canonical JSON, keyed by tenant signing key; optional KMS/HSM.

## Security requirements

1. Credentials are single-use and bound to `args_hash`; reuse or deviation invalidates instantly.
2. Master secrets never enter agent runtime memory, logs, or the model context window.
3. Every decision produces a tamper-evident receipt chained per agent.
4. Per-tenant key isolation; envelope encryption at rest.
5. Fail-closed on policy-engine or issuer error (configurable per policy: fail-open only for
   explicitly read-only, non-sensitive resources).

## Observability

- Red metrics: authorize latency p50/p99, issuance latency, issuer error rate.
- Usage: brokered credentials/day, unique agents, unique tools.
- Security: deny rate, anomaly rate, revocation events, receipt verification failures.

## Rollout plan (90 days)

| Weeks | Deliverable |
|---|---|
| 1–2 | RFC + threat model + receipt schema + repo scaffold |
| 3–5 | Rust broker: `Authorize`, CEL policy, issuers: AWS STS, GitHub App, Stripe |
| 6–8 | TS SDK + MCP adapter + Postgres graph + signed receipts |
| 9–10 | Python SDK, dashboard v1, docs, `examples/` demos |
| 11 | OSS launch (npm/PyPI + docs + demo) |
| 12 | 5 design partners; brokered-credentials instrumentation; seed one-pager |

## Open questions

- Policy language: pure CEL vs. CEL + a small DSL for intent scopes? (v0 ships a
  constraint model — max/min numbers, allowlist, prefix, required — pending CEL.)
- Where to anchor receipts in phase 1: DB-only, or DB + optional testnet anchor?
- Silent-proxy mode feasibility per provider (TLS interception vs. SDK-only)?
- How to attribute intent when the agent does not declare one (heuristic + confidence)?

## Implementation notes (v0)

- **Wire format:** camelCase JSON; receipt signed with EIP-712
  `Receipt(bytes32 payloadHash, bytes32 prev, bytes32 agentIdHash, bytes32 nonce)`.
- **AWS STS:** `AssumeRole` enforces a **900-second minimum**, so the ephemeral credential
  cannot be shorter than 15 minutes even though the *policy grant* is scoped tighter.
  SigV4 is hand-rolled (no SDK dependency). Session policy restricts to the requested
  action/ARN.
- **GitHub:** App JWT (RS256, 9-minute TTL) exchanged for an installation access token.
  The `installation_id` must be supplied in the call args.
- **Stripe:** no per-request STS, so the broker holds the narrowest restricted key and
  returns an opaque `grant_id` with `proxy_required: true`. `redeem()` enforces the
  `args_hash` match and single-use semantics; the proxy endpoint is the next milestone.
- **Receipts:** deny decisions are also signed so refusals are auditable. `receiptId` is the
  receipt's `payload_hash` and is used to link recorded outcomes.
- **Policy:** deterministic constraint model (max/min number, allowlist, prefix, required)
  plus an optional **CEL** `condition` per grant, evaluated over `resource`, `agent_id`,
  `user_id`, and every top-level argument field (nested objects via dotted access). CEL
  parse failures are contained with `catch_unwind` and fail closed (unless `fail_open`).
- **Chain:** every authorization and recorded outcome is appended to a per-agent chain where
  each receipt's `prev` is the previous receipt's `payload_hash`. Storage is pluggable via the
  `ChainStore` trait: `MemoryChainStore` (dev/tests) and `PostgresChainStore` (production).
  Append is optimistic — the entry is inserted only if its `prev` equals the stored head — and
  the Postgres path serializes per agent with `pg_advisory_xact_lock`; the service retries on
  conflict. `verify_chain` checks signatures and links; `/v1/chain/:agent` returns the chain
  and a `verified` flag.
- **Proxy:** `/v1/proxy` redeems a broker-held grant (re-checking `args_hash`, expiry, and
  single-use), then forwards exactly one request to the provider using the issuer's `ProxySpec`
  (`base_url` + auth header/scheme). Paths must be relative (no host injection). This is how
  Stripe is used without exposing the restricted key.
- **Signing key:** `BROKER_SIGNING_KEY` must be stable. Chain verification recovers the signer
  from each signature (so it survives restarts), requires every receipt in a chain to share the
  same recovered signer, and — when the key is configured — pins it to that address (detecting a
  wholesale chain replacement). Outside demo mode the broker refuses to start with a random key.

## Next milestones

1. Run the broker as a non-superuser Postgres role in production (RLS is a no-op for superusers); supply `TENANT_SECRET_ENC_KEY` from a KMS in production.
2. Stripe-native key rotation (Stripe exposes no programmatic key-delete API).
3. Execute a third-party audit and address findings (brief + controls matrix are ready).
4. Multi-replica anchoring coordination (avoid duplicate submissions across replicas).

## Implementation notes (v1.4 additions)

- **SSRF guard on tenant URLs.** `netguard.rs` validates tenant anchor RPC URLs: http(s) only,
  no embedded credentials, and private / loopback / link-local / metadata hosts are refused
  unless `ANCHOR_RPC_ALLOW_PRIVATE=1` or the host is in `ANCHOR_RPC_ALLOWLIST`.
- **Retention.** `RETENTION_DAYS` enables an hourly sweep that prunes terminal anchor records
  and telemetry for idle resources; chains already have `prune_idle_agents`. Revocations are
  deliberately retained.
- **Bounded telemetry.** Distinct string values per (resource, field) are capped (64), so
  attacker-chosen values cannot grow storage unbounded.
- **Outbound timeouts.** All broker egress uses a shared client with 5s connect / 15s total
  timeouts.
- **Constant-time key comparison.** In-memory API-key lookups compare hashes in constant time.

## Implementation notes (v1.3 additions)

- **Secrets at rest.** Tenant anchor signing keys are encrypted (ChaCha20-Poly1305,
  `TENANT_SECRET_ENC_KEY`) before they are persisted; the API never returns them
  (`hasPrivateKey` only). Storing a tenant key without an encryption key is refused.
- **Anchor submission claims.** Before submitting, the broker *claims*
  `(tenant, agent, merkle_root)`; a live claim (and a partial unique index in Postgres)
  prevents a second replica or concurrent call from submitting the same root. Failed
  submissions release the claim; reorged anchors can be re-claimed.
- **Bounded credential stores.** Grant/installation-token stores prune expired entries and
  stay bounded beyond a cap, so a caller cannot exhaust memory. Stripe grants can be held in
  Postgres (`stripe_grants`, restricted key envelope-encrypted under
  `TENANT_SECRET_ENC_KEY`) so redemption survives a restart and works across replicas; the
  in-memory store remains the default for dev/tests.
- **Proxy input validation.** Content-type values with control characters and oversized
  query parameters are rejected before the upstream request is built.

## Implementation notes (v1.1 additions)

- **Tenant-scoped chains.** `ChainStore` is keyed by `(tenant, agent)`, so two tenants may
  reuse an agent name without sharing (or contaminating) a chain; ownership checks are no
  longer needed for reads (another tenant's chain is simply empty). Postgres uniqueness moved
  to `(tenant, agent, seq)` / `(tenant, agent, payload_hash)` and a partial unique index on
  `(tenant, agent, prev_hash)` makes forks impossible at the storage layer; unique violations
  surface as optimistic-append conflicts.
- **Idempotent outcomes.** `record` re-checks for an existing outcome on every append retry and
  links the outcome explicitly to the authorization receipt (`authorizationReceiptId =
  receiptId`; older immediate outcomes use `prev`).
- **Proxy hardening.** Method allowlist (GET/POST/PUT/PATCH/DELETE/HEAD), relative-path
  enforcement, and a 1 MiB provider-response cap.
- **Public-route limiting.** Verify/metrics are rate limited per client IP
  (`PUBLIC_RATE_LIMIT_PER_MIN`, default 120) via `ConnectInfo`; `/healthz` is never throttled.

## Implementation notes (v1.0 additions)

- **Rate limiting:** a `RateLimiter` trait with `MemoryRateLimiter` (token bucket) and
  `RedisRateLimiter` (fixed window via `INCR`/`EXPIRE`), selected by `REDIS_URL`. Fails open
  on Redis error.
- **KMS/HSM signing:** a `DigestSigner` trait (`LocalSigner` in-process, `HttpKmsSigner` over
  HTTP) used by both `ReceiptSigner` (EIP-712) and `EthSigner` (EIP-1559). Configured via
  `KMS_SIGNER_URL` + `KMS_SIGNER_ADDRESS`; when set, `BROKER_SIGNING_KEY`/`ANCHOR_PK` are not
  required. A mock-KMS round-trip test covers receipt and anchor signing.
- **Anchor confirmation:** `eth.rs` reads the tx receipt (status + block number);
  `anchor_and_record` records `confirmed`/`failed`/`submitted` with the block; the scheduler
  runs `reconfirm_anchors` each sweep to update pending anchors.
- **Audit readiness:** `docs/audit-readiness.md` (scope, invariants, reproduction, known
  limits), a `cargo-fuzz` harness under `apps/broker/fuzz`, and a CycloneDX SBOM workflow.

## Implementation notes (v0.8 additions)

- **Cross-language parity:** receipt payload hashing is verified against shared fixtures in
  Rust (`apps/broker/tests/parity.rs`) and TypeScript
  (`packages/receipt-schema/test/parity.test.ts`). Canonical JSON now emits integral floats
  without a fractional part (`0.0` → `0`) so `serde_json`/`ryu` matches JS `toString`. The TS
  SDK computes real Keccak-256 (`@noble/hashes`).
- **Idempotent outcomes:** `POST /v1/record` returns the existing outcome (`duplicate: true`)
  instead of appending twice when the same authorization receipt is recorded again.
- **Rate limiting:** per-tenant token bucket (`RATE_LIMIT_PER_MIN`), enforced in the auth
  middleware (429). Local per replica; Redis-backed limiting is the next step.
- **Tests:** concurrency stress (25 parallel authorizations → consistent chain) and an
  auto-policy accuracy test (proposals generalize in-distribution and block amount/allowlist
  drift).
- **CI:** `.github/workflows/ci.yml` runs Rust (with Postgres + Foundry so the anvil anchoring
  test executes), TS typecheck + SDK/receipt-schema tests, the golden path (mock Stripe +
  anvil + broker), and the contract suite.

## Implementation notes (v0.7 additions)

- **Scheduled anchoring:** `anchors` + `anchor_targets` stores (memory / Postgres). The
  scheduler (`ANCHOR_INTERVAL_SECS`) sweeps every tenant/agent chain and anchors any whose
  root changed since the last record; `GET /v1/anchors` lists records. Per-tenant
  `GET/PUT /v1/anchor-config` selects chain/RPC/contract (and an optional signing key),
  enabling multi-chain anchoring.
- **Provider-native revocation:** credentials carry a `reference` (`cred_<provider>_<opaque>`).
  `POST /v1/revoke` with `kind: "credential"` calls the issuer's `revoke_credential`; GitHub
  performs `DELETE /app/installations/:id/access_tokens`. Stripe remains broker-grant
  invalidation (no delete API); AWS STS cannot be revoked early.
- **Cache:** `Cache` trait with in-memory and Redis (`REDIS_URL`) backends; API-key
  authentication is cached (`CachedApiKeyStore`), cleared on create/revoke.
- **Metrics:** dependency-free counters at `GET /metrics` (Prometheus text).
- **Helm:** `infra/k8s/helm/tessera` deploys the broker with probes, ConfigMap/Secret, and
  optional ingress.
- **Spec:** `docs/receipt-spec.md` publishes receipt v1 (fields, hashing, EIP-712, chain,
  Merkle, verification, versioning).

## Implementation notes (v0.6 additions)

- **Auto-policy proposal:** every allowed call records the *shape* of its arguments (numeric
  ranges, small string value sets) into a telemetry store (memory / Postgres). `GET
  /v1/policies/propose` turns the aggregate into a draft policy — numeric min/max, allowlists
  for low-cardinality strings, and `required` for consistently-present fields. Raw payloads
  are never stored.
- **On-chain anchoring:** `eth.rs` implements RLP + EIP-1559 signing (k256) and a minimal
  JSON-RPC client. `POST /v1/chain/:agent/anchor/submit` calls
  `ReceiptAnchor.anchor(bytes32,bytes32,uint64)`. An anvil-gated test deploys the contract,
  submits an anchor, and asserts `latestRoot(tenant) == root` via `eth_call`.
- **Revocation fabric:** a revocation registry (memory / Postgres) for agents and grants.
  Agent revocation blocks new authorizations; grant revocation also drops the broker-held
  grant. `POST /v1/revoke` returns the provider capability
  (`broker-grant-invalidation` | `native` | `unsupported`).
- **Independent verifier:** `receipt.rs` exposes a key-independent `Domain` plus free
  `digest`/`recover`/`verify`. Public endpoints `POST /v1/verify/receipt`, `/v1/verify/chain`,
  `/v1/verify/merkle`, and `GET /v1/verify/domain` let anyone verify without broker trust.

## Implementation notes (v0.5 additions)

- **Auth:** every route except `/healthz` requires a per-tenant API key (`Authorization:
  Bearer` or `x-api-key`). Keys are `tsk_<24 random bytes base64url>`; only the SHA-256 hash
  is stored (`api_keys` table / in-memory). The auth middleware resolves the tenant and
  injects it; handlers read it via an `Extension<Tenant>`. Key management is
  `GET/POST /v1/keys` + `DELETE /v1/keys/:id` (admin token or demo). Demo mode accepts
  `x-tessera-tenant` and seeds `TESSERA_DEMO_KEY`; `TESSERA_BOOTSTRAP_TENANT` mints a key at
  startup and prints it once.
- **SDK ↔ broker e2e:** `packages/sdk-ts/test/e2e.test.ts` spawns the broker binary in demo
  mode and drives the real SDK through authorize → record → anchor, then verifies the chain
  via the raw endpoint. Skipped if the binary is not built.
- **Reference agent:** `examples/governed-agent` runs the full loop and branches on
  credential material (bearer/AWS direct, grant via the proxy).
- **Console:** `apps/portal` is the product console (chain explorer + verify + anchor,
  policy editor, key management) backed by the Vite dev proxy to `localhost:8787`.

## Implementation notes (v0.4 additions)

- **CEL cache:** compiled programs (and compile failures) are memoized in a process-wide
  `Mutex<HashMap>`; the parser panic is contained via `catch_unwind`. Tests assert
  `Arc::ptr_eq` on repeated compilation.
- **Policy CRUD:** `PolicyStore` is async and supports `list`/`get`/`upsert`/`delete`, with
  in-memory and Postgres impls (`policies` table, `ON CONFLICT DO UPDATE`). Exposed at
  `GET/PUT/DELETE /v1/policies[/:id]`, tenant-scoped.
- **Transport tests:** AWS STS and GitHub issuers are exercised against local mock servers.
  `AWS_STS_ENDPOINT` overrides the STS endpoint; the test asserts the SigV4 `Authorization`
  header, `X-Amz-Date`, form body (`Action=AssumeRole`, `DurationSeconds=900`, `Policy=`), and
  parses the returned credentials. The GitHub test asserts a `Bearer <RS256 JWT>` (decoded
  header `alg`/`typ`) and parses the installation token.
- **Partitioning & retention:** `receipt_chain` is `PARTITION BY HASH (agent)` with 8
  partitions, so unique `(agent, …)` constraints hold and each chain stays in one partition.
  `migrate()` upgrades an ordinary table in place. `prune_idle_agents(cutoff)` deletes whole
  agents (never mid-chain) and returns the row count.
- **Anchoring:** `merkle.rs` builds a sorted-pair `keccak(min‖max)` tree matching
  `ReceiptAnchor._verify`; `build_batch` returns the root, leaves, the last leaf's proof, and
  ABI calldata for `anchor(bytes32,bytes32,uint64)` (selector `0x15954b2c`).
  `GET /v1/chain/:agent/anchor` returns the batch. A cross-language test pins the same root in
  Rust and Solidity.

## Implementation notes (v1.5 hardening)

- **Startup endpoint validation:** `bootstrap::build_service` validates every configured
  endpoint via `netguard::validate_endpoint` (shape) and `RpcPolicy` (tenant RPC: private
  ranges blocked unless explicitly allowed), and checks them against `EGRESS_ALLOWLIST` when
  set. `BrokerConfig: Default` makes fail-closed behavior testable
  (`tests/bootstrap_validation.rs`).
- **Strict egress:** `netguard::EgressGuard` (opt-in via `EGRESS_ALLOWLIST`) is consulted in
  `AuthorizeService::proxy` (before the upstream call, after redemption so grants are not
  spent on blocked egress) and in `anchor_and_record` (before submission). `host_of` was
  factored out of `RpcPolicy` and shared.
- **Per-agent budgets:** `AuthorizeService.agent_rate_limit_per_min` (env
  `AGENT_RATE_LIMIT_PER_MIN`) checks `agent:{tenant}:{agent}` through the shared
  `RateLimiter` (memory or Redis); denials surface as `BrokerError::Throttled` → **429**
  via the now-public `http::status_for` helper.

## Implementation notes (v1.6 hardening)

- **Client IP (`src/clientip.rs`):** `TrustedProxies` parses CIDR/bare-IP/`any` entries;
  `client_ip(peer, xff)` returns the peer unless it is trusted, then walks XFF right-to-left
  over trusted hops. Wired into the public-route middleware (`AppState.trusted_proxies`).
- **Limiter eviction (`ratelimit.rs`):** at capacity, evict buckets idle for >120 s, then
  least-recently-used; `MemoryRateLimiter::with_capacity` exposes the bound for tests.
- **Budgets:** `AuthorizeService.tool_rate_limits` (from `TOOL_RATE_LIMITS`) meters
  `tool:{tenant}:{resource}` for configured resources only; `AGENT_RATE_LIMIT_PER_MIN` meters
  `agent:{tenant}:{agent}`. Both return `BrokerError::Throttled` → 429.
- **TTL:** `default_ttl_seconds`/`max_ttl_seconds` come from
  `DEFAULT_CREDENTIAL_TTL_SECONDS`/`MAX_CREDENTIAL_TTL_SECONDS`; the IssueRequest TTL is
  clamped once, so every issuer inherits the ceiling. Helm `values.yaml` ships production
  defaults (trusted proxy CIDRs, TTL ceiling, 90-day retention).

## Implementation notes (v1.7 hardening)

- **Policy limits:** `PolicyLimits` is part of the policy document (no migration needed —
  policies are stored as JSONB and unknown fields default). `PolicyResult` carries the matched
  policy's limits; `authorize` meters `policy-tool:{tenant}:{resource}` and
  `policy-agent:{tenant}:{agent}` and computes `ttl = min(default, policy).clamp(1, global)`.
- **Audit export (`src/export.rs`):** `sign_hash`/`recover_hash` extend `ReceiptSigner` to
  raw digests; the manifest digest is Keccak-256 over canonical JSON with `signature` removed.
  `ExportBundle::verify` re-derives leaves via `merkle::leaf_for_receipt`, so mutating receipt
  contents (not just hashes) is detected. Route: `GET /v1/export/chain/:agent`
  (tenant-scoped), metric `tessera_export_bundles_total`.
- **Pools:** `db::connect_pool` centralizes pool options + `SET statement_timeout` in
  `after_connect`; all six Postgres stores use it.

## Implementation notes (v1.8 hardening)

- **Verify caps:** `MAX_VERIFY_ENTRIES = 1000`, `MAX_MERKLE_PROOF = 64` in `verify.rs`.
- **Export v2:** manifest digest = `keccak("tessera-export-v1" ‖ canonical JSON minus
  signature fields)`; `tenant_signer`/`tenant_signature` are optional and verified when
  present (a claimed signer without a signature is malformed). `export_chain` decrypts the
  tenant's anchor key (envelope encryption) to co-sign; the address is set before signing so
  it is covered by the signature.
- **CLI:** `src/bin/tessera-verify.rs` (auto-discovered bin) shares `ExportBundle::verify`
  with the server; tested via `CARGO_BIN_EXE_tessera-verify`.
- **Limits endpoint:** `AuthorizeService::effective_limits` merges config + policy budgets
  (tightest wins) and exposes only non-secret posture; the handler adds AppState-level
  fields (tenant/public budgets, trusted-proxy flag).

## Implementation notes (v1.9 hardening)

- **Rotation:** `AuthorizeService.signing_key_history` (from `BROKER_SIGNING_KEY_HISTORY`),
  `accepted_signers()` dedupes case-insensitively; `/v1/verify/domain` and `/v1/limits`
  expose the list. Receipts carry no key id — recovery identifies the signer, and verification
  accepts membership in the published set.
- **Tenant export:** `export_chain` was refactored around `build_agent_export` (one
  digest computed after `tenant_signer` is set; broker + tenant signatures over it), reused
  by `export_tenant`. The aggregate manifest re-uses the `tessera-export-v1` domain tag via
  `tenant_manifest_digest`.
- **Snapshots:** `payload_digest`/`sign_payload`/`verify_signed_payload` generalize
  domain-tagged signing; `LIMITS_DOMAIN = "tessera-limits-v1"`.
- **CLI:** accepts single-agent bundles, tenant bundles, and `--limits` snapshots; repeated
  `--expect-signer` flags model a key history.

## Implementation notes (v2.0 hardening)

- **Anchor proofs (`receipt_proof`):** locates the receipt by payload hash or index, picks the
  tightest live anchor whose `count` covers it, rebuilds the leaves for `chain[..count]` and
  confirms the recomputed root equals the stored root before emitting a proof (cap
  `MAX_EXPORT_RECEIPTS`). On-chain check via `RpcClient::get_logs` (topic0 =
  `Anchored(bytes32,uint256,bytes32,uint64,uint64)`, topic1 = tenant hash) matching the root
  word in the log data; confirmations = head − block + 1.
- **Archive (`build_tenant_archive`):** `tar` + `flate2` (miniz_oxide), built in memory;
  README text is generated from the manifest so an auditor never has to consult the docs.
- **Keygen:** `LocalSigner::private_key_hex()` is exposed for tooling only; the server never
  serializes key material.

## Implementation notes (v2.1 hardening)

- **Gaps:** `AuthorizeService::anchor_gaps` (chain length vs newest live anchor per agent);
  `scheduler::report_anchor_gaps` logs/counts once per sweep; `GET /v1/anchors/gaps` returns
  `{ threshold, items[] }` for dashboards. Agents with no anchor are reported with
  `lastAnchoredCount: 0`.
- **Archives:** `write_tenant_archive` reuses `export_tenant` + `build_tenant_archive`;
  filenames are timestamped and tenant-sanitized; `scheduler::archive_tenants` iterates
  `chain.tenants()` on `ARCHIVE_INTERVAL_SECS` (floor 60 s).
- **Scheduler wiring:** the sweep loop now also runs when only `ARCHIVE_DIR` is set (interval
  falls back to 60 s), and archives fire on the first tick so evidence exists at startup.
- **CLI `--archive <dir>`:** rebuilds the `TenantExportBundle` from an extracted archive;
  README text is generated with the working command.
- **Tenant rotation:** `set_anchor_target` derives the prior key's address (decrypting via the
  envelope) and appends it to `signer_history`; rotating to a key already in history is
  rejected by removing the matching entry from history (i.e. the new key wins, history stays
  unique). HTTP callers cannot inject history directly.

## Implementation notes (v2.2 hardening)

- **Healing:** `AuthorizeService::heal_anchor_gaps(tenant, max_agents)` runs from
  `scheduler::report_anchor_gaps`; requires a configured anchor and threshold; errors are
  logged per agent, never propagated.
- **Index:** appended with `OpenOptions::append`; each line is the payload object plus a
  `snapshot` (`SignedPayload`) so the same verifier used for limits snapshots applies.
  File names are `tessera-export-<tenant>-<utc>-<8 hex>.tar.gz`.
- **Per-key budgets:** `ApiKeyStore::authenticate` returns the full `ApiKeyRecord` (breaking
  change, all call sites updated); `CachedApiKeyStore` caches the serialized record so the
  budget is not lost on cache hits; `ApiKeyBudget` is a request extension consumed by
  `/v1/limits`.

## Implementation notes (v2.3 hardening)

- **Scopes:** `KeyScope { resources, agents }` on `ApiKeyRecord`; matching reuses
  `policy::resource_matches` (public); enforced in `authorize_handler`/`record_handler` via
  the `ApiKeyScope` request extension; persisted as JSONB (`ADD COLUMN IF NOT EXISTS`).
- **Replication:** performed inside `write_tenant_archive` after the index append; the copy is
  re-read and compared by Keccak-256 digest.
- **Alerts:** `AuthorizeService::alert_anchor_gap` (repeat suppression via a mutex-guarded map
  of `(tenant, agent) -> Instant`); the scheduler calls it from `report_anchor_gaps`.
  `ALERT_WEBHOOK_URL` is shape-validated and egress-checked at startup like other endpoints.

## Implementation notes (v2.4 hardening)

- **Key options:** `NewKeyOptions { rate_limit_per_min, scope, expires_at }` replaces the
  growing positional parameter list; `record_is_live` centralizes revoked/expired semantics;
  the auth cache caps its TTL by the key's remaining life.
- **Alerts:** `alerts.rs` (`AlertRouter` + memory store) and `alerts_pg.rs` (JSONB events);
  `AuthorizeService::send_alert` is the single delivery path (repeat suppression keyed by
  tenant+event+dedup id, retry on failure); `set_alert_target` reuses the RPC policy and the
  secrets envelope.
- **Restore:** `src/bin/tessera-restore.rs` shares `ExportBundle`/`TenantExportBundle`
  verification with the broker; writes are ordered so verification precedes any output.

## Implementation notes (v2.5 hardening)

- **Renewal:** `ApiKeyStore::renew` replaces the stored hash for the same id (PG:
  `UPDATE ... WHERE tenant/id AND revoked_at IS NULL`, `rotation_count + 1`); the cached store
  clears its cache on success.
- **Import:** `import_chain` verifies payload hashes + per-receipt signatures
  (`receipt::recover` against `accepted_signers`), then merges by walking the local chain and
  the bundle in lock-step; the tail is appended through `ChainStore::append`, which enforces
  linkage and surfaces conflicts for a single re-read retry.
- **Acks:** `alert_acks` (+ pg) stores `(tenant, event, dedup_key) -> severity`; `send_alert`
  consults it before the repeat window and bypasses that window on escalation;
  `report_anchor_gaps` / `report_expiring_keys` prune acks for conditions no longer present.

## Implementation notes (v2.6 hardening)

- **Import refactor:** `inspect_import` performs validation (tenant, bundle verify, accepted
  signer, per-receipt signature + payload hash) and builds the drift report; `import_report`
  returns it, `import_chain` refuses on divergence and appends the missing suffix.
- **Rotation:** `auth::rotation_due_hours` is a pure function (unit-tested); the scheduler
  wraps it, alerts with event `key.rotation-due`, and the severity is `overdue_hours`.
- **Auto-ack:** `AlertRouter::auto_ack_below` (tenant target wins over the global config,
  `.with_auto_ack()`); `send_alert` checks it before the ack store and repeat window.

## Implementation notes (v2.7 hardening)

- **Ledger:** `KeyEvent` with `event_digest` (domain ‖ prev ‖ canonical JSON minus
  hash/signature); the broker signs the digest, so `verify_chain` covers linkage *and*
  authenticity. Memory + PG stores; appends happen after successful store operations in the
  HTTP layer (create/renew/revoke), never on failure.
- **Checkpoints:** `detect_drift` is a pure function (unit-tested); `write_tenant_archive`
  writes a checkpoint per archived agent; `chain_drift` slices the live chain at the
  checkpointed index to compare prefixes.
- **Quota:** `QuotaManager` holds per-provider semaphores (lazy) plus per-provider/per-tenant
  semaphores, bounded at 10k tracked tenants; `proxy` uses `grant_provider`, issuance uses
  `provider_for(resource)`.

## Implementation notes (v2.8 hardening)

- **Export bindings:** `TenantExportManifest` gains `key_events_digest` / `checkpoints_digest`
  (canonical hashes via `export::digest_of`); `export_tenant` re-signs after adding them, so
  the tenant + broker signatures cover the ledger and checkpoints. `TenantExportBundle::verify`
  checks ledger linkage before comparing the digest. Archives add `key-events.json` /
  `checkpoints.json`; both CLIs read them so manifests verify after extraction.
- **Integrity:** `integrity_report` is a service method; the HTTP handler adds key posture from
  the key store (which lives on `AppState`).
- **Quota:** `QuotaManager::snapshot` walks the semaphore maps (lazily created) and reports
  `cap - available_permits`.

## Implementation notes (v2.9 hardening)

- **Snapshots:** `write_signed_snapshot` signs any posture payload with `INTEGRITY_DOMAIN`,
  writes `integrity-<tenant>-<ts>-<rand>.json`, and appends a signed index entry with
  `kind`; archive entries now carry `kind: "archive"` too. `GET /v1/integrity?sign=true`
  attaches the same snapshot shape. `auth::key_posture` is shared by the dashboard, the
  snapshot writer, and tests.
- **Drift re-archive:** `report_chain_drift` collects affected tenants and re-archives them
  when `ARCHIVE_DIR` is set; the fresh checkpoint clears the drift while old archives remain.
- **Attestations:** `SignedPayload` is camelCase on the wire (API consistency); the broker
  attests imports, the CLI attests restores with the operator's key, and both verify through
  `verify_signed_payload` under `RESTORE_DOMAIN`.

## Implementation notes (v3.0 hardening)

- **Diffs:** `previous_snapshot` picks the newest `integrity-<tenant>-*.json` (lexicographic
  order is chronological), strips `snapshot`/`changes`, and `diff_snapshots` compares a fixed
  field list with directionality (`unexpected` for rewinds, new drift, or a ledger that stops
  verifying).
- **Ledger:** `append_ledger_event(tenant, kind, subject, subject_name, prefix, details)`
  generalizes the key-event append; `append_key_event` delegates to it and `import_chain`
  appends `chain.imported` carrying `attestationDigest`.
- **Retention:** `prune_evidence` parses the fixed-width timestamp in file names (naive UTC;
  the literal `Z` is stripped), keeps the newest snapshot per tenant, appends a signed
  `retention.pruned` entry, and counts `tessera_evidence_pruned_total`. Index verification
  skips metadata-only entries and tolerates pruned files.

## Implementation notes (v3.1 hardening)

- **Proxy scope:** `Issuer::peek_grant_resource` (default `None`; Stripe implements it from
  the stored grant) is surfaced as `IssuerRegistry::grant_resource`. `proxy_scoped` checks
  scope → pre-redeem peek → redeem → post-redeem re-check.
- **Agent routes:** `agent_allowed(&scope, agent)` guards chain, anchor, submit, proof, and
  per-agent export handlers; tenant-wide evidence endpoints stay tenant-level by design.
- **Idempotency:** the handler hashes nothing — it uses `<tenant>:<key id>:<value>` in the
  shared `Cache` (memory or Redis), storing the serialized `AuthorizeResponse`; the cache also
  backs API-key auth, so Redis deployments get cross-replica replay for free.

## Implementation notes (v3.2 hardening)

- **Capabilities:** `KeyScope.capabilities` + `allows_capability`/`effective_capabilities`;
  `create_key` validates against `KEY_CAPABILITIES` (400 on unknown). Guards:
  `capability_allowed` on authorize/proxy/record plus every read handler (chain, anchor,
  submit, proof, per-agent export, anchors, gaps, tenant export/archive, integrity, key
  events, alert config, limits).
- **Idempotency:** `idempotency_cache_key(headers, tenant, key id)` shared by authorize,
  record, and proxy; responses are serialized into the shared cache with
  `IDEMPOTENCY_TTL_SECS`.

## Implementation notes (v3.3 hardening)

- **Updates:** `ApiKeyStore::update(tenant, id, scope, Option<Option<u32>>)` (Postgres uses
  `COALESCE`/`CASE` so omitted fields are preserved); HTTP treats a scope update as a full
  replacement and validates capabilities against `KEY_CAPABILITIES`.
- **Templates:** `key_templates()` returns `(name, description, KeyScope)`; the create handler
  short-circuits into the same `NewKeyOptions` path and records the template name in the
  ledger details.
- **SDKs:** `CallOptions`/`WrapOptions` in TS; `_mutation_headers` in Python.
- **Test hygiene:** temp-dir helpers now append an atomic counter to their clock-based suffix
  (macOS clock resolution is coarse enough for two threads to collide), which eliminated a
  flaky cross-test interference in `verify_cli`.

## Implementation notes (v3.4 hardening)

- **Proxy paths:** `KeyScope.proxy_paths` matched with `policy::resource_matches` (exact or
  trailing-`*`); enforced at the top of `proxy_scoped`, before the grant peek/redeem.
- **Linting:** `scope_exceeds(scope, template)` compares capabilities, resources, agents and
  proxy paths, using `pattern_covers` for pattern-vs-pattern coverage; unrestricted
  dimensions are reported as over-grants.
- **Versions:** `ApiKeyRecord.version` starts at 1, bumps on every mutation in both stores
  (Postgres `version = version + 1`); `key_etag` renders `"v<n>"`; the PATCH handler compares
  the `If-Match` value against the freshly-read record before updating.

## Implementation notes (v3.5 hardening)

- **Mutations:** `ApiKeyStore::renew/revoke` take `expected_version` and return
  `MutateOutcome<T>` (`Done`/`NotFound`/`Conflict{current}`); Postgres uses
  `AND ($n::int IS NULL OR version = $n)` and reports the current version on conflict.
  `ApiKeyRecord` derives `PartialEq` so outcomes are comparable in tests.
- **Templates:** `KeyTemplate { name, description, scope, default_rate_limit_per_min }`;
  `GET /v1/key-templates` serializes the struct directly.
- **Remediation:** dry-run/apply share the lint comparison; apply performs a scope-replacing
  `update` per key (version-checked) and appends `key.scope-remediated`.

## Implementation notes (v3.6 hardening)

- **Events:** `AuthorizeService::send_event` shares signing/transport with `send_alert` but
  skips acks and the repeat window; the HTTP layer emits via `emit_key_event` after every
  successful mutation.
- **Policy:** `RemediationPolicyStore` (memory + Postgres) keyed by tenant;
  `remediation_decision` is a pure read; `apply_auto_remediation` performs the
  version-checked narrowing and ledger append in the HTTP layer (the service never owns the
  key store).
- **Previews:** `scope_diff(before, after)` reports per-dimension adds/removes; the dry-run
  path includes `before`, `after`, and `diff` without mutating anything.

## Implementation notes (v3.7 hardening)

- **Templates:** `payments-integration.scope.proxy_paths = ["/v1/refunds*"]`.
- **Preview:** reuses `scope_exceeds` + `scope_diff`; reports the current policy alongside the
  preview so the caller sees the delta from what is already enforced.
- **Replay:** `key_event_log(tenant, since, limit)` verifies the full ledger, then filters and
  pages; `parse_cursor` tolerates the query-string mangling of `+00:00` and accepts unix
  seconds for cursor stability.

## Implementation notes (v3.8 hardening)

- **Paging:** `build_agent_export_page(tenant, agent, from, limit)` slices by chain index;
  `ExportBundle::verify` accepts a page only when `from_index > 0` carries `prev_before` and a
  zero-index bundle carries none, and rejects `next_from <= from_index`.
- **Deliveries:** `AuthorizeService::send_event` returns `alerts::Delivery { attempted,
  delivered, status }`; `emit_key_event` appends `webhook.delivery` only when a delivery was
  attempted (no destination = no receipt).
- **Templates:** `KeyTemplate.version` (currently 1 for all presets); `PUT
  /v1/remediation-policy` stores the current revision; the staleness check runs before any
  narrowing decision.

## Implementation notes (v3.9 hardening)

- **Idempotency:** `idempotent(state, cache_key, request_hash, execute)` replaces the three
  hand-rolled replay blocks; `AuthorizeRequest`/`RecordRequest`/`ProxyRequest` derive
  `Serialize` so fingerprints are canonical JSON hashes.
- **Health check:** reuses `submitter_for` (tenant target or global anchor) and `egress`
  policy; `RpcClient::code_at` adds `eth_getCode`.
- **Compaction:** `KeyEventStore::compact(tenant, cutoff, checkpoint)` is atomic per store
  (memory: retain + push; Postgres: insert checkpoint then delete by id in one transaction);
  `verify_chain` anchors on the first surviving event when a checkpoint is present and exempts
  the checkpoint from the local link check (its digest/signature are still verified).

## Implementation notes (v4.0 hardening)

- **Settings authorization:** `put/get/check` anchor-config, `put/get/delete` alert-config, and
  `get/put/delete` remediation-policy all call `keys_allowed` (admin token, or demo mode).
  Demo mode keeps first-run flows working; production requires the admin token.
- **Heavy routes:** a `heavy_route_limit` middleware attached per-route (export, tenant export,
  archive, import, proof) sharing one `heavy:{tenant}` bucket from `HEAVY_ROUTE_RATE_LIMIT_PER_MIN`.
- **Fee cap:** `config::anchor_max_fee_per_gas()` reads `ANCHOR_MAX_FEE_PER_GAS_WEI` at
  submitter construction; `submit` compares the computed `max_fee` before signing.

## Implementation notes (v4.1 hardening)

- **Audit:** `audit_setting_change(state, tenant, setting, action, before, after)` uses
  `append_ledger_event` with kind `setting.changed`; handlers capture `before` via the same
  redaction helpers used for reads, so secrets never reach the ledger.
- **Redaction:** `url_host` (shared with the scheduler) reduces a URL to `host[:port]`;
  `redact_target_public` / `redact_alert_target_public` produce the reader-facing shapes.
- **Snapshots:** `integrity_snapshot_payload` embeds `settings.{anchor,alert,remediation}` plus
  `settings.digest` (canonical hash); `diff_snapshots` gained a `settings.digest` field.

## Implementation notes (v4.2 hardening)

- **Fail-safe demo mode:** `config::demo_allow_from(Option<&str>)` accepts `1|true|yes`
  (case-insensitive) and treats unset/empty/anything else as disabled; `BrokerConfig::from_env`
  feeds it `TESSERA_DEMO_ALLOW`. The golden path, SDK e2e, and example READMEs already opt in
  explicitly.
- **Redaction + audit:** `url_host`, `redact_target_public`, `redact_alert_target_public`, and
  `audit_setting_change` (see v4.1 notes) are exercised live on a non-demo broker: admin sees
  full URLs, readers see hosts, and settings writes from a read-only key are rejected.
- **Operational note:** demo mode makes every caller an admin by design, so redaction is only
  observable with `TESSERA_DEMO_ALLOW` off and an admin token configured.

## Implementation notes (v4.3 hardening)

- **Import:** `inspect_import` validates `prev_before` against `existing[from_index-1]` and
  compares receipts at `from_index + offset`; `import_chain` tracks a running `local_len` so a
  page applies entry by entry and refuses entries beyond the local head with a page-aware
  message.
- **Patterns:** `invalid_scope_patterns(scope) -> Vec<String>` (provider-scoped wildcards only,
  absolute proxy paths) is called by create and update handlers; templates already comply.
- **Metrics:** `metrics_handler(headers)` checks `METRICS_TOKEN` when configured, using
  `auth::ct_eq`.

## Implementation notes (v4.4 hardening)

- **Chain paging:** `chain_handler` clamps `limit` to 1..=5000, defaults to
  `AppState.chain_read_limit` (env `CHAIN_READ_LIMIT` at bootstrap), slices `entries[from..end]`,
  and reports `hasMore`/`nextFrom`; the verification verdict is computed on the full chain.
- **Indexed record:** `ChainStore::find_by_prev` (default scans `chain()`; Postgres queries
  `prev_hash` with a dedicated index); `record` uses `find` + `find_by_prev` + `len`.
- **Anchors:** `GET /v1/anchors?limit=` returns the newest page with `count`/`returned`/`hasMore`.

## Implementation notes (v4.5 correctness)

- **`find_outcome`:** default filters `find_by_prev` on `call.result_hash.is_some()`; Postgres
  filters with `(receipt -> 'call' -> 'resultHash') IS NOT NULL` on the same indexed
  `prev_hash` lookup.
- **Ordering rule:** `record` verifies `head_hash == receipt_id` before building the outcome
  receipt and returns `Invalid` otherwise; the 16-attempt contention loop now only covers
  genuine concurrent appends.

## Implementation notes (v4.6 bug-fix pass)

- **Authz:** admin gates on `import`/`revoke`; `authorize` on anchor submission; `read` on
  integrity/revocations. Tested as a matrix in `write_routes_require_the_right_authorization`.
- **Agent ids:** `auth::valid_agent_id` enforced in authorize/record/import;
  `auth::safe_agent_filename` used by `build_tenant_archive` and `tessera-restore`.
- **CEL:** `cache_lock()` recovers from poisoning; eviction clears at `MAX_CACHED_PROGRAMS`;
  `execute` is wrapped in `catch_unwind(AssertUnwindSafe(..))`.
- **Fix details:** `prune_evidence` uses `rsplitn(3, '-')`; `ExportBundle::verify` accepts an
  empty page with `prev_before` and no head; alert-config handlers read `alert_router.target`.

## Implementation notes (v4.7 hardening)

- **Tool pins:** `tool_pins.rs` (+ `tool_pins_pg.rs`) stores the approved definition and its
  canonical hash; `authorize` requires a matching `toolSchemaHash` for pinned tools, denies
  before issuance, and appends `tool.drift` with `expected`/`received`. Receipts record
  `call.toolHash`. `PUT/GET/DELETE /v1/tools` are admin/read-gated and audit pin changes.
- **Policy audit:** policy upsert/delete append `policy.changed` with `{policyId, version,
  action, digest|digestBefore}` before returning; digest is `hash_json(Policy)`.
- **Telemetry:** `looks_sensitive` marks emails, long digit runs, and token/JWT/PEM prefixes
  as `<redacted>`; proposals never allowlist the marker.
- **SDK/MCP:** `receipt-schema` exports `toolDefinitionHash` (parity fixtures shared with
  Rust); the TS SDK forwards `toolSchemaHash`; the MCP adapter accepts `toolDefinitions`
  (from `tools/list`) and sends the hash per call.
- **Startup migrations:** `AuthorizeService::migrate` now covers every store (`chain`,
  policies, telemetry, revocations, anchors, key events, alert targets/acks, remediation,
  checkpoints, tool pins) and `main` calls it once; previously `key_events`, alert targets,
  alert acks, remediation policies, and checkpoints were never migrated in the Postgres
  deployment, so audit writes failed at request time. Covered by
  `migrations_postgres::startup_migrates_every_store`.

