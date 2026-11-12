# Threat Model

Scope: the Agent Action Broker and shared control plane. Method: asset-centric with adversary
goals, following STRIDE-style categories. Living document.

## Assets

| Asset | Sensitivity |
|---|---|
| Master provider secrets (AWS, GitHub, Stripe, OAuth) | critical |
| Issued ephemeral credentials | high (TTL-scoped) |
| Policy definitions & versions | high |
| Receipt ledger & signing keys | high |
| Intent→capability telemetry graph | high (cross-tenant aggregate) |
| Tenant/user identity & delegation chains | high |

## Adversaries

1. **Malicious agent / prompt injection** — an agent is coerced via untrusted content.
2. **Compromised agent host** — attacker has code execution in the agent runtime.
3. **Malicious insider** — tenant user abusing legitimate access.
4. **Network attacker** — MITM on agent↔broker traffic.
5. **Curious infrastructure provider** — cloud/operator access to secrets.
6. **Competitor / scraper** — wants the telemetry corpus.

## Threats & mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | Exfiltrate master secrets from broker | Secrets in isolated secret store; broker holds TTL-scoped material only; envelope encryption; HSM/KMS in later phase |
| T2 | Replay / reuse an issued credential | Single-use, bound to `args_hash`, 30s TTL; deviation invalidates instantly |
| T3 | Authorization bypass via forged intent | Intent is validated against policy + user RBAC + resource allowlist; anomaly scoring; deny-by-default |
| T4 | Receipt forgery or ledger tampering | Chained receipts (`prev` hash), EIP-712 signatures, optional Merkle anchor on-chain |
| T5 | Cross-tenant action / isolation escape | Per-tenant keys and policy namespaces; issuer scoping; no shared credential material |
| T6 | MITM on agent↔broker | TLS at the public edge and private broker network; short-lived SDK tokens; receipt signing pins trust to the broker key. mTLS is not implemented yet. |
| T7 | Policy engine DoS / latency spike | Cache decisions in Redis; bounded CEL evaluation time; redundancy; fail-closed |
| T8 | Anomalous-but-authorized bulk action | Per-agent rate/cost budgets; anomaly detector on the graph; step-up for sensitive resources |
| T9 | Telemetry corpus exfiltration | Aggregate-only exports by default; tenant-scoped access; no raw cross-tenant data |
| T10 | Prompt-induced secret in logs/context | Never place raw secrets in model context or logs; log hashes only |

## Trust boundaries

- Agent runtime is **untrusted**.
- Broker and secret store are **trusted** (highest hardening).
- Issuers are **trusted but scoped** — least-privilege exchange requests.
- Chain anchor is **trust-minimized** (verification, not secrecy).

## Implemented controls (v0.9 hardening)

| Control | Detail |
|---|---|
| Tenant isolation | Chains are keyed by `(tenant, agent)` (two tenants may reuse an agent id without sharing a chain); grants/credential references are bound to the issuing tenant |
| SSRF / egress control | Tenant-supplied anchor RPC URLs must be http(s), credential-free, and non-private unless explicitly allowed (`ANCHOR_RPC_ALLOW_PRIVATE` / `ANCHOR_RPC_ALLOWLIST`) |
| Retention | Terminal anchors and idle telemetry are pruned after `RETENTION_DAYS`; chains have whole-agent pruning |
| Bounded telemetry | Distinct string values per (resource, field) are capped so attacker-chosen values cannot grow storage unbounded |
| Outbound timeouts | A shared client bounds connect (5s) and total (15s) time on all broker egress |
| Secrets at rest | Tenant anchor signing keys are envelope-encrypted (ChaCha20-Poly1305) before persistence and never returned by the API; a missing encryption key refuses the write |
| Submission coordination | Anchors are *claimed* per `(tenant, agent, merkle_root)`; a partial unique index prevents duplicate on-chain submissions across replicas, with stale claims re-anchored |
| Bounded stores | Grant/token stores prune expired entries; the in-memory grant store is capped, and the Postgres grant store persists envelope-encrypted grants across restarts/replicas |
| Proxy input validation | Control characters in `contentType` and oversized query parameters are rejected |
| RLS (defense in depth) | `app.tenant` is set per tenant transaction; `infra/sql/rls.sql` enforces tenant policies so an unfiltered query still cannot cross tenants (non-superuser role required) |
| Anchor finality / reorg | Anchors progress `submitted → confirmed → finalized` with block numbers; a tx missing beyond the grace period is marked `reorged` and re-anchored |
| Provider revocation breadth | GitHub (installation token delete), Stripe (broker-grant invalidation), AWS (inline deny policy scoped to `sts:RoleSessionName`) |
| Chain integrity | Postgres enforces `UNIQUE (tenant, agent, seq)` and a partial unique index on `(tenant, agent, prev_hash)`, so forks are impossible at the storage layer; outcomes re-check idempotency on every append retry |
| Secret redaction | `Debug` for `CredentialMaterial`, `RedeemedGrant`, `StoredGrant`, `AwsConfig`, `GithubConfig`, `StripeConfig` redacts tokens/keys so secrets cannot reach logs |
| Idempotency | `POST /v1/record` returns the existing outcome for a repeated authorization receipt instead of forking the chain |
| Rate limiting | Per-tenant token bucket (`RATE_LIMIT_PER_MIN`); per-IP budget for public verify/metrics routes (`PUBLIC_RATE_LIMIT_PER_MIN`, default 120); shared Redis fixed window when `REDIS_URL` is set; 429 |
| Proxy hardening | Only ordinary HTTP methods (GET/POST/PUT/PATCH/DELETE/HEAD) forwarded; relative paths only; provider responses capped at 1 MiB |
| Request limits | Body cap (`MAX_BODY_BYTES`, default 64 KiB → 413) and request timeout (`REQUEST_TIMEOUT_SECS`, default 30s → 408) |
| Anchor confirmation | Tx receipt polled for status + block; records `confirmed`/`failed`; scheduler reconfirms pending anchors |
| Key custody | Receipt + anchor signing via local key or a KMS/HSM bridge (`KMS_SIGNER_URL`); secrets redacted from `Debug` |
| Cross-language parity | Receipt payload hashing verified identical in Rust and TypeScript against shared fixtures |
| Property tests | Canonical JSON idempotence, Merkle proof soundness, CEL panic-freedom, RLP boundaries |
| Fuzzing | `cargo-fuzz` targets for canonical JSON, CEL, Merkle, RLP, receipt parsing |

## Residual risks / accepted for now

- SDK-only integration cannot stop a user who bypasses the SDK entirely; the silent-proxy mode is a
  later mitigation and is provider-dependent.
- Model providers do not expose weights; provenance is over hashes and signed I/O, not internal state.
- Rate limiting is shared only when Redis is configured; the in-memory limiter is per replica.
- KMS/HSM custody depends on the operator-provided bridge; the in-process key remains the default.
- Anchor confirmation is best-effort (bounded poll). Reorged txs are detected and re-anchored; a chain-level rollback of already-finalized roots is not attempted.
- RLS requires a non-superuser role: superusers bypass policies, so the operator must run the broker as an app role (documented in `docs/rls.md`).
- No third-party audit yet; `docs/audit-readiness.md` prepares one. Schedule it with a design partner.

## Controls added in v1.5 (hardening pass)

- **Endpoint validation at startup (fail closed).** Every operator-configured endpoint
  (anchor RPC, AWS STS/IAM overrides, GitHub API base, Stripe API base, KMS signer) is
  checked for scheme (http/https), absence of embedded credentials, and host presence
  before the broker serves traffic. A malformed endpoint aborts boot with a labeled error.
- **Optional strict egress.** With `EGRESS_ALLOWLIST=host[:port],…` set, outbound calls to
  any other host are refused — enforced at the proxy (after grant redemption, before the
  upstream call) and at anchor submission. This is defense in depth against operator
  misconfiguration or a compromised config source: even if a base URL is tampered with, the
  call never leaves the allowlisted hosts.
- **Per-agent rate limits.** `AGENT_RATE_LIMIT_PER_MIN` adds a second budget keyed by
  `(tenant, agent)` on the authorize path, independent of the tenant budget, so one runaway
  or compromised agent cannot consume the whole tenant's quota. Throttled requests return
  **429** (new `BrokerError::Throttled`) and increment the deny metric.

## Controls added in v1.6 (hardening pass)

- **Spoof-resistant client IP (`TRUSTED_PROXIES`).** Behind Caddy/ingress, the TCP peer is the
  proxy, so per-IP public limits keyed on it would be one shared bucket *and* a direct client
  could rotate `X-Forwarded-For` to mint fresh budgets. Forwarded headers are now honored only
  when the peer is a configured trusted proxy, and the rightmost untrusted hop is used. Empty
  list = trust none.
- **Rate-limiter bounded without a reset button.** The in-memory limiter no longer clears all
  buckets at capacity (an attacker who filled 50k keys could reset every caller's budget);
  it evicts idle buckets first, then the least-recently-used, so live budgets survive.
- **Credential TTL ceiling.** `DEFAULT_CREDENTIAL_TTL_SECONDS` (30) and
  `MAX_CREDENTIAL_TTL_SECONDS` (3600) bound every issued credential at the single choke point
  in `authorize`; the GitHub issuer caps its reported TTL at GitHub's enforced one hour so the
  broker never over-claims.
- **Per-resource budgets (`TOOL_RATE_LIMITS`).** `resource=per_minute` pairs meter provider
  blast radius (e.g. refunds) independently of the tenant/agent budgets. Only configured
  resources are metered, so bucket cardinality is bounded by config, not request input.

## Controls added in v1.7 (hardening pass)

- **Self-serve policy limits.** Policies may carry `limits` (`max_ttl_seconds`,
  `agent_rate_limit_per_min`, `tool_rate_limits`). Enforcement happens after evaluation on
  allowed calls, and limits can only *tighten*: effective TTL is
  `min(policy, broker default)` clamped by the broker ceiling, and policy budgets stack on
  top of the global ones. Policies are tenant-scoped, so a tenant cannot loosen another's
  posture.
- **Signed audit export.** `GET /v1/export/chain/:agent` returns the agent's receipts plus a
  manifest (contract version, tenant, count, chain length, head, Merkle root, signer) signed
  over its canonical-JSON digest. `ExportBundle::verify` checks linkage, the Merkle root, the
  signature, and receipt contents offline — no broker trust or database access. Tampering
  with a receipt body, a payload hash, or any manifest field fails verification. Exports are
  capped at 5,000 receipts (`truncated: true` + `chain_length` when clipped).
- **Database hardening.** Every store uses a shared pool builder (bounded connections, 10 s
  acquire timeout, idle/lifetime recycling) with a 30 s server-side `statement_timeout`, so
  one pathological query cannot pin a connection or a CPU slice indefinitely.
- **Smaller fixes.** Admin token comparison is constant-time; a panic in any handler returns
  500 via `CatchPanicLayer` instead of dropping the connection.

## Controls added in v1.8 (hardening pass)

- **Bounded verification work.** `/v1/verify/chain` and `/v1/verify/merkle` are public and
  CPU-bound, so `verify.rs` now refuses chains longer than 1,000 entries and Merkle proofs
  longer than 64 hashes before doing any cryptography.
- **Export signatures are domain-separated and optionally tenant-signed.** The manifest
  digest mixes in `tessera-export-v1`, so an export signature can never be replayed as any
  other Tessera signature. When the tenant has its own signing key (the same key used for
  on-chain anchors), the manifest is co-signed: auditors can anchor trust in the tenant, not
  only the broker. A configured-but-unusable key fails the export loudly rather than
  emitting a bundle that looks tenant-signed.
- **Offline verification.** `tessera-verify <bundle.json> [--expect-signer 0x…]
  [--expect-tenant-signer 0x…]` verifies linkage, Merkle root, both signatures and receipt
  contents without the broker, its database, or network access (exit 0/1/2).
- **Posture introspection.** `GET /v1/limits` reports the caller's effective limits (tenant,
  agent, per-resource budgets merged from config + policies, TTLs, retention, strict-egress
  and distributed-limiter flags) — no secrets, useful for dashboards and support.
- **Throttle metrics.** `tessera_throttled_total` counts every rejection by any budget
  (tenant, agent, per-resource, policy-level, public IP) for alerting.

## Controls added in v1.9 (hardening pass)

- **Key rotation without losing verifiability.** `BROKER_SIGNING_KEY_HISTORY` lists previous
  signer addresses; `/v1/verify/domain` now returns `signers` (current first, then history,
  deduplicated) so verifiers keep accepting receipts signed before a rotation. The offline
  CLI accepts repeated `--expect-signer` flags for the same purpose.
- **Tenant-wide exports.** `GET /v1/export/tenant` returns a signed archive: one sub-bundle
  per agent (each individually verifiable) plus an aggregate manifest covering
  `agent_count`, `receipt_count`, per-agent heads, and a combined Merkle root over every
  leaf, with anchor records attached. Caps: 100 agents, 5,000 receipts per agent, each
  flagged via `truncated`. Tampering with any single agent bundle fails the aggregate.
- **Evidence-grade posture snapshots.** `GET /v1/limits?sign=true` attaches a domain-tagged
  (`tessera-limits-v1`) broker signature over the canonical posture payload;
  `verify_signed_payload` rejects any modification, and `tessera-verify --limits <file>`
  checks it offline. Useful as change-of-record evidence in support and audit workflows.

## Controls added in v2.0 (hardening pass)

- **Anchor ↔ receipt cross-verification.** `GET /v1/chain/:agent/proof?receipt=0x…` (or
  `?index=n`) returns the Merkle leaf, proof, root, and the covering anchor record, rebuilt
  from the append-only chain prefix so the root can be re-derived — not merely quoted. When
  a tenant RPC target is configured, the broker also performs `eth_getLogs` for the
  `Anchored` event carrying that root and reports `blockNumber`, `confirmations`, and the
  on-chain batch index (`checked: false` when no RPC is configured, never a silent pass).
- **Auditor archive.** `GET /v1/export/tenant/archive` returns one `tar.gz` containing a
  README (how to verify, domain tags, expected signers), the aggregate manifest, each
  per-agent bundle, and anchor records. Every agent bundle verifies standalone; the archive
  is bounded by the same caps as the JSON export.
- **Rotation.** `tessera-keygen` generates keys and derives addresses without echoing key
  material into logs; `docs/rotation.md` documents the publish-history-first rotation, the
  verification commands for both old and new artifacts, and emergency-rotation steps.

## Controls added in v2.1 (hardening pass)

- **Anchor gap detection.** Every sweep compares each agent's chain length with its last live
  anchor; agents past `ANCHOR_GAP_THRESHOLD` (default 100) are logged, counted
  (`tessera_anchor_gap_events_total`), and listed by `GET /v1/anchors/gaps` with the gap size,
  last anchor status, and timestamp. A silent anchoring outage is now visible instead of
  implicit.
- **Scheduled tenant archives.** With `ARCHIVE_DIR` set, the scheduler writes a signed
  `tar.gz` per tenant on an interval (`ARCHIVE_INTERVAL_SECS`), independent of the database:
  the evidence survives DB loss, corruption, or retention. Failures are counted
  (`tessera_archive_failures_total`); the broker never prunes these files (operator policy).
- **Archive verification directory mode.** `tessera-verify --archive <dir>` verifies an
  extracted archive (manifest + per-agent bundles + anchors) as a whole; the generated README
  ships that exact command, so an auditor never has to guess. Tampering with any file fails.
- **Tenant key rotation.** Publishing a new tenant key records the previous key's address in
  `signer_history` automatically (and refuses to rotate back to a historical key, which would
  be ambiguous). `GET /v1/anchor-config` exposes the history; `accepted_tenant_signers`
  returns current + historical addresses so verifiers can keep accepting older co-signed
  exports. Persisted as a JSONB column with an `ADD COLUMN IF NOT EXISTS` migration.

## Controls added in v2.2 (hardening pass)

- **Gap-triggered anchoring.** When a chain is flagged past `ANCHOR_GAP_THRESHOLD`, the sweep
  immediately forces an anchor for up to 10 agents per tenant instead of waiting for the next
  pass. Submission claims still dedupe by `(tenant, agent, root)`, so forcing cannot double
  submit; attempts and successes are counted (`tessera_anchor_gap_heal_attempts_total`,
  `tessera_anchor_gap_healed_total`).
- **Signed archive index.** Every scheduled archive appends a signed entry to
  `INDEX.jsonl` (`tessera-archive-index-v1`): file name, Keccak-256 digest, size, counts,
  Merkle root, timestamp. `tessera-verify --archive-index <dir> [--check-files]` verifies each
  line's signature and re-hashes the referenced archives, so a deleted or rewritten archive is
  detectable after the fact. Archive file names now carry a random suffix — two archives in
  the same second can no longer overwrite each other.
- **Per-API-key budgets.** `POST /v1/keys` accepts `rateLimitPerMin`; the authorization
  middleware meters `apikey:{tenant}:{key_id}` before the tenant budget, so one integration
  cannot exhaust a tenant's quota. Stored per key (memory + Postgres column with
  `ADD COLUMN IF NOT EXISTS`), reported by `GET /v1/limits` as `keyRateLimitPerMin`, and the
  auth cache now carries the full record so budgets survive caching.

## Controls added in v2.3 (hardening pass)

- **Key-scoped permissions.** API keys can be issued with `allowedResources` (`stripe:*`)
  and `allowedAgents`. The scope is enforced in the HTTP layer *before* policy evaluation and
  credential issuance, so a leaked integration key cannot even ask for resources it was not
  issued for. Scope is stored per key, reported by `GET /v1/limits`, and never widens a
  tenant's policies (it only narrows).
- **Archive replication.** With `ARCHIVE_REPLICA_DIR`, each archive is copied to a second
  location and the copy is read back and digest-compared before being counted. A replica
  failure never fails the primary archive; it is logged and counted
  (`tessera_archive_replica_failures_total`).
- **Anchor-gap alerts.** With `ALERT_WEBHOOK_URL`, the sweep POSTs a domain-tagged
  (`tessera-alert-v1`) signed event when a chain crosses the gap threshold, optionally
  authenticated with `x-tessera-alert-token`. Alerts are repeat-suppressed per
  `(tenant, agent)` for `ALERT_REPEAT_SECS`; delivery is best-effort and counted
  (`tessera_alerts_sent_total`, `tessera_alert_failures_total`). Failed deliveries retry after
`ALERT_RETRY_SECS` (default 60) rather than being suppressed for the full repeat window —
a receiver outage cannot hide a gap for an hour.

## Controls added in v2.4 (hardening pass)

- **API-key expiry.** Keys can be created with `ttlSeconds` or an explicit `expiresAt`.
  Expired (and unparseable-date) keys behave exactly like revoked ones — rejected in both
  stores and never cached past their remaining lifetime.
- **Key-expiry alerting.** The sweep reports keys expiring within `KEY_EXPIRY_ALERT_DAYS`
  (default 7): a metric, a warning log, and a signed `key.expiring` webhook through the same
  routing as gap alerts.
- **Restore drill.** `tessera-restore <archive-dir> --out <dir>` verifies an evidence archive
  in full and only then writes `chain-<agent>.jsonl` plus a `restore.json` summary. A tampered
  archive is refused with nothing written — the DR path can never ingest unverified data.
- **Per-tenant alert routing.** `PUT /v1/alert-config` sets a tenant webhook (event filter,
  optional token). URLs are tenant-supplied and go through the same SSRF policy as anchor RPC
  URLs; tokens are encrypted at rest and never returned (`hasToken` only). Alerts fall back to
  the operator-wide webhook when no tenant target matches.

## Controls added in v2.5 (hardening pass)

- **In-place key renewal.** `POST /v1/keys/:id/renew` rotates the secret while preserving the
  key id, name, scope, budget and rotation history. The previous secret stops working
  immediately (hash replaced, auth cache cleared); `rotation_count`/`rotated_at` record the
  rotation for audit.
- **Chain import from signed evidence.** `POST /v1/import` accepts an export bundle only after
  verifying the manifest *and* every receipt's own signature against the accepted signer set.
  Receipts already present are skipped, so replaying an archive is idempotent and a partially
  restored chain is completed; divergence from the local chain is refused rather than
  overwritten. Any foreign signer or tampered content is rejected.
- **Alert acknowledgements.** `POST /v1/alerts/ack` records the severity a tenant has seen;
  repeats stay quiet until the condition *worsens* (an escalation bypasses the repeat window,
  because it is new information). Acks are pruned automatically when the condition clears, so
  a recurrence alerts again. Alert payloads carry a signed `conditionValue`.

## Controls added in v2.6 (hardening pass)

- **Rotation-age alerting.** `KEY_ROTATION_MAX_AGE_HOURS` reports any live key not rotated
  within the window (age measured from the last rotation, else creation), with the overdue
  hours as the severity. It complements expiry alerting: expiry says "this key will stop
  working", rotation says "this secret has been in use too long".
- **Non-destructive drift report.** `POST /v1/import?dryRun=true` validates a bundle and
  compares it to the local chain (matched / missing / first divergent index / heads) without
  writing anything, so operators can assess a restore before committing to it.
- **Auto-ack policies.** A severity floor (`ALERT_AUTO_ACK_BELOW`, or per-tenant
  `autoAckBelow` on the alert target) suppresses low-severity alerts entirely — counted
  (`tessera_alerts_auto_acked_total`) and logged, never delivered — so only escalations page
  anyone. An explicit acknowledgement still allows an escalation to bypass the repeat window.

## Controls added in v2.7 (hardening pass)

- **Key-event ledger.** Key creation, renewal and revocation append a signed, hash-linked
  event (`keccak(domain ‖ prev ‖ canonical(event))`). `GET /v1/key-events` returns the tenant's
  ledger with a verdict; edits, deletions or reordering break linkage. Key management finally
  has the same tamper-evidence as receipts.
- **Chain drift detection.** Archiving records a checkpoint per agent (head + count). The
  sweep compares live chains against checkpoints and raises `chain.drift` when receipts are
  missing or a previously checkpointed prefix was rewritten (severity ranks rewrites above
  data loss). Silent history editing therefore pages instead of hiding.
- **Provider quota reservations.** `PROVIDER_MAX_INFLIGHT` /
  `PROVIDER_MAX_INFLIGHT_PER_TENANT` cap concurrent provider work per provider and per tenant,
  covering both credential issuance and proxying. Permits are RAII (released on drop, even on
  failure), so one tenant's burst cannot consume a shared upstream limit; rejections are 429
  and counted (`tessera_quota_rejections_total`).

## Controls added in v2.8 (hardening pass)

- **Self-contained evidence.** Tenant export bundles now carry the key-event ledger and the
  chain checkpoints, each bound into the signed manifest by a canonical digest. An archive
  therefore proves not only what receipts existed, but which keys existed and what the chains
  looked like when archived — and tampering with either section fails verification.
- **Integrity dashboard.** `GET /v1/integrity` summarises a tenant's posture in one call:
  chains (agents/receipts/unanchored/drifted), anchors (count/pending/latest), ledger verdict
  (count + validity), checkpoints, and key posture (active/expiring/rotation-due). Support and
  operators get one place to look instead of five.
- **Quota observability.** `/v1/limits` reports current reservations per provider (cap,
  in-flight, per-tenant cap, tracked tenants), so an operator can see capacity pressure
  before it becomes a rejection.

## Controls added in v2.9 (hardening pass)

- **Scheduled integrity snapshots.** Each archive pass also writes a signed posture snapshot
  (`tessera-integrity-v1`) into the evidence directory and indexes it in the same append-only
  index, so retention has periodic, tamper-evident proof of what the system looked like —
  not just at archive time but across the whole window.
- **Drift-triggered re-archiving.** When drift is detected the tenant is re-archived
  immediately so a fresh checkpoint records reality; the pre-drift archive stays on disk and
  indexed, which is what makes the rewrite provable. Drift then clears, so alerts stop
  without operator action while the evidence remains.
- **Restore attestations.** `POST /v1/import` returns a broker-signed certificate of what was
  imported (counts, head before/after, bundle head and root). `tessera-restore --attest
  <file> --signing-key 0x…` adds an operator-signed certificate, verifiable offline with
  `tessera-verify --attestation <file> --expect-signer 0x…`. Restores are now auditable
  events, not just file writes.

## Controls added in v3.0 (hardening pass)

- **Signed snapshot diffs.** Each new integrity snapshot is compared with the previous one on
  disk; the change list is attached to the payload *before* signing, so posture deltas are
  part of the evidence. Changes that indicate evidence loss, new drift, or a broken ledger
  (`unexpected`) raise an `integrity.changed` alert — growth is recorded but silent.
- **Restores are first-class ledger events.** The broker-signed import certificate is linked
  into the tenant's hash-linked ledger as `chain.imported` (carrying the attestation digest),
  so restores share the same tamper-evident history as key events and travel in exports.
- **Evidence retention with proof.** `ARCHIVE_RETENTION_DAYS` prunes old archives and
  superseded snapshots while always keeping the append-only index and the newest snapshot per
  tenant. Every deletion is recorded as a signed `retention.pruned` entry, and
  `tessera-verify --archive-index --check-files` distinguishes "pruned by policy" from
  "missing" — silence can no longer hide a deleted file.

## Controls added in v3.1 (hardening pass)

- **Key scope on grant redemption.** API-key scopes were enforceable on authorize/record but
  *bypassable on `/v1/proxy`*: any key in the tenant could redeem a grant issued under a
  different key's scope. The broker now peeks at the grant's resource (non-consuming) and
  denies a mismatched key **before** redemption, so a denied request cannot burn the
  single-use credential. A post-redeem check remains as defence in depth.
- **Agent scopes on agent routes.** Keys scoped to specific agents are now enforced on every
  agent-specific route (chain, anchor, anchor submission, receipt proof, per-agent export),
  not just on authorize/record — a scoped integration can no longer read another agent's
  chain or evidence.
- **Idempotent authorize.** `Idempotency-Key` on `/v1/authorize` replays the original response
  for the configured window (`IDEMPOTENCY_TTL_SECS`, default 600), scoped per tenant and API
  key. Client retries after a timeout can no longer mint duplicate credentials or receipts.
- **Import-sized bodies.** `/v1/import` has its own body cap (`MAX_IMPORT_BYTES`, default
  8 MiB): bundles were previously rejected above the 64 KiB default, making large restores
  impossible through the API.

## Controls added in v3.2 (hardening pass)

- **Per-key capabilities.** Scopes now carry an operation allow-list (`authorize`, `proxy`,
  `record`, `read`; empty = all). Every route checks the capability it needs, so a leaked
  proxy-only integration key cannot mint credentials, and a read-only monitoring key cannot
  write. Key management is deliberately *not* delegatable: it stays behind the admin token,
  so a leaked integration key cannot mint more keys.
- **Effective capabilities in `/v1/limits`.** Callers can see exactly what their key may do
  (explicit list, or the full set when unrestricted) alongside budgets and scope.
- **Idempotent record and proxy.** Both accept `Idempotency-Key` with the same replay
  semantics as authorize: a retried outcome report returns the original receipt, and a
  retried proxy returns the original response **without calling the provider again** —
  eliminating the double-charge risk on timeout retries.

## Controls added in v3.3 (hardening pass)

- **Audited scope/budget changes.** `PATCH /v1/keys/:id` replaces a key's scope (or clears/sets
  its budget) in place; the auth cache is cleared immediately and the change is recorded in
  the hash-linked ledger as `key.scope-changed` / `key.budget-changed` with before/after
  values. Privilege reductions take effect on the next request and are provable afterwards.
- **Named key templates.** `GET /v1/key-templates` publishes presets (`monitor`,
  `payments-integration`, `cloud-provisioner`, `repo-automation`); `POST /v1/keys {"template":
  "…"}` resolves one into a canonical scope. Templates are mutually exclusive with explicit
  scope fields, so an integrator cannot accidentally combine a narrow preset with a broad
  override.
- **SDK ergonomics.** The TypeScript client takes `idempotencyKey` on authorize/record/proxy,
  `wrapFn`/`wrap` generate one per invocation (covering the authorize + record pair), and the
  Python client accepts `idempotency_key` — retries are safe by default instead of by
  convention.

## Controls added in v3.4 (hardening pass)

- **Per-key proxy path allowlists.** A scope can restrict which upstream paths its grants may
  hit (`/v1/refunds*`). The check runs before redemption, so a denied path neither reaches the
  provider nor burns the single-use grant — a leaked key's blast radius is bounded by path as
  well as by resource.
- **Over-grant linting.** `GET /v1/keys/lint?template=monitor` audits live keys against a
  preset and explains *why* each one exceeds it ("key allows every capability", "capability
  'authorize' is outside the template", …), turning least-privilege from an aspiration into a
  report you can act on.
- **Optimistic concurrency on key updates.** Every key carries a monotonic `version` (bumped
  by scope/budget changes, renewal and revocation) exposed as an ETag; `PATCH /v1/keys/:id`
  honours `If-Match` and returns 412 on a stale revision, so two admins editing the same key
  cannot silently clobber each other's scope changes.

## Controls added in v3.5 (hardening pass)

- **Conditional renewal and revocation.** `POST /v1/keys/:id/renew` and
  `DELETE /v1/keys/:id` honour `If-Match`, and the check is enforced **inside the store's
  update** (`WHERE ... AND version = $n`), so a rotation can no longer race a concurrent
  scope change: the loser gets 412 with the current revision instead of silently winning.
- **Lint-driven remediation.** `POST /v1/keys/lint {"template": "...", "apply": true}`
  narrows every over-granted key to the preset's scope. Dry runs report without changing
  anything; applied remediations are conditional updates and are recorded per key in the
  hash-linked ledger (`key.scope-remediated` with reasons and before/after).
- **Template default budgets.** Presets carry a `defaultRateLimitPerMin`
  (monitor 60, payments 120, cloud/repo 60), applied when a template-created key has no
  explicit budget — a preset key is never accidentally unbounded. Explicit budgets still win.

## Controls added in v3.6 (hardening pass)

- **Key lifecycle webhooks.** Every key change (created, renewed, revoked, scope-changed,
  auto-remediated) is pushed to the tenant's webhook as a signed `key.lifecycle` event. These
  are *discrete* events: no repeat suppression or acknowledgement applies, so an integration
  always sees the full key history in order.
- **Remediation previews.** The dry-run lint now returns the exact scope diff per key
  (`add`/`remove` per dimension) alongside the reasons, so an operator can review precisely
  what applying would change before committing.
- **Auto-remediation policy.** `PUT /v1/remediation-policy {"template": "monitor"}` makes the
  broker narrow keys that exceed the template **as they are created or widened**, recording
  each narrowing in the ledger (`key.auto-remediated`) and pushing a lifecycle event. Least
  privilege becomes the default path rather than an audit that runs later.

## Controls added in v3.7 (hardening pass)

- **Policy-aware templates.** The `payments-integration` preset now bounds proxying to
  `/v1/refunds*` — the narrowest path that satisfies the reference integration — and the
  template comparator already inspects proxy paths, so keys that ignore the bound are flagged
  and (with auto-remediation enabled) narrowed.
- **Tenant-wide policy preview.** `POST /v1/remediation-policy/preview {"template": "..."}`
  shows every key that enabling the policy would narrow, with the exact scope diff, without
  storing the policy or touching any key — safe to run before committing to enforcement.
- **Ledger replay.** `GET /v1/key-events?since=<cursor>&limit=<n>` pages the ledger for
  integrations that were offline. The signature verdict always covers the *full* ledger (a
  page cannot be hash-verified alone), cursors accept RFC 3339, space-decoded `+00:00`, bare
  timestamps, or unix seconds, and `hasMore`/`nextSince` make paging explicit.

## Controls added in v3.8 (hardening pass)

- **Template versioning.** Presets carry a revision; remediation policies pin the revision they
  were approved against. If a preset is revised, existing policies go **stale** and stop acting
  (counted in `tessera_remediation_stale_total`) until an operator re-approves — changing a
  preset can never silently change what is enforced.
- **Paged evidence exports.** `GET /v1/export/chain/:agent?from=<index>&limit=<n>` returns a
  deterministic slice of a chain with a signed `from_index`/`prev_before`/`next_from`, so
  chains longer than the export cap are fully recoverable page by page and every page verifies
  on its own (a page that hides its continuation, or lies about its predecessor, fails).
- **Webhook delivery receipts.** Every lifecycle delivery attempt is appended to the ledger as
  `webhook.delivery` with the event, action, HTTP status, and outcome — an integration (or an
  auditor) can prove exactly what was sent and whether it arrived, including failures.

## Controls added in v3.9 (hardening pass)

- **Idempotency keys are bound to the request.** The cache entry now stores a canonical
  fingerprint of the request alongside the response: reusing a key with a *different* body is
  rejected with 409 instead of silently replaying an unrelated credential/receipt, and nothing
  is created for the rejected attempt.
- **Anchor target health check.** `POST /v1/anchor-config/check` probes the tenant's RPC and
  contract without submitting anything: reachability, chain id vs. the configured value, and
  whether code is actually deployed at the address. Misconfigurations surface as a report
  rather than as failed anchor submissions.
- **Ledger compaction.** `LEDGER_RETENTION_DAYS` prunes old ledger entries behind a signed
  `ledger.compacted` checkpoint that names the last pruned hash; verification anchors on that
  checkpoint, so storage stays bounded while tampering with the gap remains detectable (the
  checkpoint's digest and signature are verified like any other event).

## Controls added in v4.0 (hardening pass)

- **Tenant settings are admin-only.** The anchor configuration (RPC URL and — critically — the
  tenant signing key), the alert webhook (URLs commonly embed shared secrets), and the
  remediation policy now require admin authorization on every method. Previously any
  authenticated key in the tenant could repoint on-chain anchoring at its own signer or
  redirect alerting to an attacker-controlled URL.
- **Heavy-route budgets.** Export, import, receipt-proof, and archive endpoints have their own
  per-tenant budget (`HEAVY_ROUTE_RATE_LIMIT_PER_MIN`), so one client cannot monopolize a
  replica's CPU building bundles and hashing archives within its ordinary request budget.
- **Anchor fee ceiling.** `ANCHOR_MAX_FEE_PER_GAS_WEI` makes submission fail closed when the
  computed fee exceeds the cap, instead of paying whatever the chain asks during a fee spike
  or on a misconfigured network.

## Controls added in v4.1 (hardening pass)

- **Settings changes are audited.** Anchor, alert, and remediation configuration changes (and
  deletions) append `setting.changed` events to the tenant's hash-linked ledger, with
  before/after values redacted to non-secret fields. Combined with the signed snapshot digest,
  configuration is now as auditable as key lifecycle.
- **Redacted settings reads.** Read-capable keys can see a host-only summary of the anchor RPC
  and alert webhook (paths and query strings commonly embed provider keys or Slack/Discord
  secrets) plus `hasPrivateKey`/`hasToken`; only the admin token returns full URLs. Least
  privilege no longer means "no visibility".
- **Settings in signed snapshots.** Integrity snapshots carry the (redacted) settings block and
  its canonical digest; `settings.digest` changes appear in the snapshot diff, so configuration
  drift shows up in evidence even before the ledger is consulted.

## Controls added in v4.2 (hardening pass)

- **Demo mode is opt-in only (fail-safe default).** `TESSERA_DEMO_ALLOW` previously defaulted to
  `"1"`, so any deployment that omitted the variable ran with demo semantics: full tenant
  access from the `x-tessera-tenant` header without an API key, a permissive policy injected
  for tenants with no policies, and every caller treated as an administrator for key and
  settings management. The default is now **disabled**; it must be enabled explicitly and is
  documented as never-for-production. Startup logs `demo=false` unless opted in.
- **Redacted settings reads.** Read-capable keys see host-only summaries of the anchor RPC and
  alert webhook (paths/queries commonly embed provider keys or Slack-style secrets) plus
  `hasPrivateKey`/`hasToken`; only the admin token returns full URLs. Verified live: admin sees
  the full URL, a read-only key sees `host`, and the same key's write attempt is 403.
- **Settings audit trail.** Anchor/alert/remediation changes append `setting.changed` events to
  the tenant's hash-linked ledger with before/after values redacted — and the hidden URL path
  is proven absent from the audit entry in tests and live output.

## Controls added in v4.3 (hardening pass)

- **Page-aware chain import.** Paged bundles now import with correct offsets: a page can only
  be applied when the local chain already contains its matching predecessor (the check is
  explicit and the error says so), pages apply entry by entry, and the dry-run report uses
  page offsets rather than genesis offsets. Previously a page was misjudged as "missing from
  index 0" and either failed confusingly or (with a partial chain) reported nonsense.
- **Scope pattern validation.** Resource patterns must be exact, `*`, or provider-scoped
  (`stripe:*`, `aws:s3:Get*`); a typo like `stripe*` (which would also grant
  `stripeplayground:…`) is rejected at create and update time with the offending value.
  Proxy paths must be absolute (`/v1/refunds*`), so a relative pattern cannot be silently
  prefixed with a provider base.
- **Optional metrics token.** `METRICS_TOKEN` gates `/metrics` behind a bearer token compared
  in constant time; when unset the endpoint stays public (counters only, IP rate-limited).

## Controls added in v4.4 (hardening pass)

- **Bounded read endpoints.** `GET /v1/chain/:agent` now returns a page (default
  `CHAIN_READ_LIMIT`=1000, max 5000) with `from`/`returned`/`hasMore`/`nextFrom`; verification
  still covers the whole chain. `GET /v1/anchors` returns the newest 100 by default. A single
  request can no longer materialize an arbitrarily long chain or anchor history.
- **`record` is chain-length-independent.** Outcome reporting previously loaded the entire
  chain twice per call; it now uses indexed lookups (`find` by payload hash, `find_by_prev`
  with a new `receipt_chain_prev_idx` index, and `len`), so cost stays flat as chains grow.
- **Test isolation.** Two tests mutated process-wide environment variables that shaped request
  handling (`HEAVY_ROUTE_RATE_LIMIT_PER_MIN`, `CHAIN_READ_LIMIT`), which could perturb
  concurrent tests. Both limits are now fields on `AppState` configured explicitly by tests;
  six consecutive full-suite runs are clean.

## Controls added in v4.5 (correctness pass)

- **Outcome recording is unambiguous.** A successor authorization also links to the previous
  receipt, so matching "an entry whose `prev` is this authorization" could return the *next*
  authorization: recording an outcome for an older authorization silently reported a
  duplicate and returned someone else's receipt. Outcomes are now matched by result hash
  (`find_outcome`), and when the chain head has moved on the broker says so explicitly
  ("authorization is not the current chain head; record the outcome before the next
  authorization") instead of dropping data or failing opaquely after contention retries.
  **Update (current):** outcomes now carry `authorizationReceiptId` and append at the current
  chain head, so a later authorization does not block recording the earlier outcome. Old
  immediate outcomes remain verifiable via `prev`.
- **Test isolation (again).** Two more tests mutated process-wide env vars
  (`HEAVY_ROUTE_RATE_LIMIT_PER_MIN`, `CHAIN_READ_LIMIT`) that shape request handling; both
  limits are now `AppState` fields, and the suite runs clean repeatedly.

## Controls added in v4.6 (bug-fix pass)

A route-by-route authorization audit plus a panic/resource scan found and fixed:

- **Missing authorization on write/read routes.** `/v1/import` (rewrites chain evidence) and
  `/v1/revoke` (kills agents/grants) were reachable by any authenticated key and now require
  the admin token. Anchor submission required `read` instead of `authorize` (so proxy-only
  keys could spend gas and authorize-only keys were wrongly denied). `/v1/integrity` and
  `/v1/revocations` were readable by any key and now require `read`.
- **Path traversal via agent ids.** Agent ids are client-supplied and flow into archive entry
  names and restore output filenames. They are now validated at the boundary
  (`[A-Za-z0-9._:@-]`, ≤128 chars, no `..`/leading or trailing dot) and sanitised with a short
  hash suffix before use as filenames, so `agents/../…` can no longer be produced.
- **Unbounded CEL cache.** Tenant-supplied policy expressions were memoized without a limit;
  the cache is now capped (4,096), recovers from mutex poisoning, and interpreter panics are
  contained and treated as evaluation failures (deny, unless the policy fails open). Policy
  count per tenant is capped at 100 (updates remain unlimited).
- **Retention parsing.** `prune_evidence` split filenames on `-` from the left, so a
  hyphenated tenant id made old archives look malformed and **never pruned** them. Parsing now
  works from the right (timestamp/random suffix), with the tenant as the remainder.
- **Empty trailing export pages** were signed but failed `ExportBundle::verify` (head `None`
  vs predecessor) — now accepted as valid evidence and importable as no-ops.
- **Alert-config display depended on decryption.** Reading `hasToken` required decrypting the
  stored token, so rotating/restoring `TENANT_SECRET_ENC_KEY` locked admins out of the config
  they needed to fix. Reads now use the stored (still-encrypted) record and never decrypt.
- **Deployment:** the broker image pinned Rust 1.83 while the workspace is tested on 1.98;
  the image now uses `rust:1.98-slim` and builds with `--locked`.

## v4.7 — 2026 agent-threat alignment (tool supply chain, policy change, data minimisation)

Research review against NIST's agent-identity work and the OWASP Top 10 for Agentic
Applications (ASI04 supply chain / MCP03 tool poisoning) surfaced three gaps that are now
closed in-broker:

- **Tool-definition rug pulls.** Approving an MCP server is a point-in-time decision; the
  server can redefine a tool (description, schema, `destructiveHint`) after review. Tenants
  can now pin a tool (`PUT /v1/tools/:tool`, admin) which stores the canonical
  `keccak256` hash of the whole definition. Every authorize for a pinned tool must present
  `toolSchemaHash`; a missing or different hash is denied and recorded as `tool.drift` in
  the ledger. Re-approval is explicit and audited (`tool.pinned` / `tool.unpinned`).
  Receipts carry `call.toolHash` so evidence shows which definition was approved.
- **Unrecorded policy edits.** Policies are the authorization core, but updates and
  deletions left no durable trace. Create/update/delete now append `policy.changed` ledger
  events with the policy version and a canonical digest of the document (and, on delete,
  the digest of what was removed), so a reviewer can correlate authorization behaviour
  with policy history.
- **Sensitive data in the telemetry graph.** Observed argument strings are used to
  propose allowlists, which risks persisting emails, card/account numbers, and provider
  tokens. String values that look like PII or credentials (emails, long digit runs,
  `sk_`/`ghp_`/`AKIA` prefixes, JWTs, PEM blocks) are stored as `<redacted>`, never
  proposed as allowlist values, and the redaction is noted in the proposal.

