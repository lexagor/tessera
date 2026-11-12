# Controls Matrix

Maps each security invariant to its implementation and the tests that exercise it. Intended
to accompany the [audit brief](audit-brief.md) so a reviewer can jump from claim → code →
test.

Legend: **impl** = primary implementation; **tests** = suites that exercise it.

| # | Invariant | Implementation | Tests |
|---|---|---|---|
| 1 | Deny-by-default authorization; constraints + CEL; fail closed | `policy.rs` (`evaluate`, `grant_allows`, `eval_condition`) | `policy::tests::*`, `authorize_e2e::denies_*`, `property::cel_random_expressions_never_panic` |
| 2 | Credentials tenant-scoped, single-use, bound to `argsHash` | `issuers/stripe.rs` (`redeem_grant`), `issuers/github.rs`, `authorize.rs`, `proxy.rs` | `issuers::stripe::tests::*`, `proxy_e2e::*`, `authorize_e2e::*` |
| 3 | No secrets in context or logs | `issuers/mod.rs` (redacting `Debug`), `config.rs` (redacting `Debug`) | `issuers::tests::debug_redacts_secrets` |
| 4 | Receipt integrity (EIP-712 digest + recovery) | `receipt.rs` (`digest`, `sign`, `recover`) | `receipt::tests::*`, `verify::tests::*`, `kms_signer::*` |
| 5 | Chain link integrity; fork-freedom under concurrency | `chain.rs` (`verify_chain`, optimistic append), `chain_pg.rs` (advisory lock + unique link index) | `chain::tests::*`, `authorize_e2e::concurrent_authorize_keeps_chain_consistent`, `chain_postgres::*` |
| 6 | Tenant isolation (read/write, incl. same agent id) | `chain.rs`/`chain_pg.rs` (`(tenant, agent)` keys), `authorize.rs` (`record`, `anchor_batch`), `http.rs` (tenant from auth) | `chain::tests::chains_are_isolated_per_tenant`, `authorize_e2e::tenant_isolation_*`, `authorize_e2e::same_agent_id_is_isolated_per_tenant`, `rls_postgres::*` |
| 6b | Database-enforced tenant isolation (defense in depth) | `db.rs` (`tenant_tx` GUC), `infra/sql/rls.sql` | `rls_postgres::rls_restricts_unfiltered_queries` |
| 7 | Resource protection: rate/body/time limits; no existence leak | `ratelimit.rs`, `http.rs` (`require_auth`, `public_rate_limit`, `DefaultBodyLimit`, `TimeoutLayer`) | `auth_e2e::rate_limit_*`, `auth_e2e::public_routes_are_rate_limited`, `authorize_e2e::oversized_body_is_rejected` |
| 8 | Cross-language receipt hashing exactness | `canonical.rs`, `packages/receipt-schema` (`canonicalize`, `keccak256Hex`) | `parity::*` (Rust), `receipt-schema/test/parity.test.ts` (TS) |
| 9 | Revocation effectiveness (agent / grant / credential) | `authorize.rs` (`revoke`), `revocation*.rs`, `issuers/*::revoke_*` | `authorize_e2e::revoked_agent_is_denied`, `proxy_e2e::revoked_grant_blocks_proxy`, `issuers_transport::github_revokes_*`, `issuers_transport::aws_sts_revocation_*` |
| 10 | Transaction signing correctness (EIP-1559 / RLP) | `eth.rs` (`Rlp`, `EthSigner::sign_eip1559`, `AnchorSubmitter`) | `eth::tests::*`, `property::rlp_*`, `anchor_eth::anchor_end_to_end_on_anvil` |
| 11 | Independent verification without broker trust | `verify.rs`, `receipt.rs` (`Domain`, free `recover`) | `verify::tests::*`, `authorize_e2e::http_verify_*` |
| 12 | Anchor finality / reorg handling | `anchoring.rs` (`plan_reconfirmation`, `pending`), `authorize.rs` (`reconfirm_anchors`) | `anchoring::tests::reconfirmation_planner`, `chain_postgres::postgres_anchoring_*` |
| 13 | Idempotent outcomes | `authorize.rs` (`record`) | `authorize_e2e::record_is_idempotent` |
| 14 | Signing key custody (local or KMS/HSM) | `signer.rs` (`DigestSigner`, `LocalSigner`, `HttpKmsSigner`) | `signer::tests::*`, `kms_signer::*` |
| 16 | Secrets at rest are encrypted; not returned by the API | `secrets.rs` (`Envelope`), `authorize.rs` (`set_anchor_target`, `private_key_plaintext`), `http.rs` (`redact_target`) | `secrets::tests::*`, `authorize_e2e::anchor_target_key_is_encrypted_and_redacted` |
| 17 | Anchor submission claims (no duplicate on-chain submits) | `anchoring.rs` (`claim`, partial unique index), `anchoring_pg.rs`, `authorize.rs` (`anchor_and_record`) | `anchoring::tests::claim_*`, `chain_postgres::postgres_anchor_claims_*` |
| 18 | Bounded credential stores; durable Stripe grants in Postgres | `issuers/stripe.rs` (memory/Postgres grant stores, encrypted secret), `issuers/github.rs` (prune + cap) | `issuers::stripe::tests::grant_store_is_bounded`, `chain_postgres::postgres_grants_are_durable_and_single_use` |
| 19 | Proxy input validation | `proxy.rs` (method allowlist, path/query/content-type checks, response cap) | `proxy::tests::*`, `proxy::hardening_tests::*`, `proxy_e2e::oversized_provider_response_is_rejected` |
| 20 | SSRF / egress control on tenant URLs | `netguard.rs` (`RpcPolicy`), `authorize.rs` (`set_anchor_target`) | `netguard::tests::*`, `authorize_e2e::tenant_rpc_urls_are_ssrf_checked` |
| 21 | Retention of terminal anchors + idle telemetry | `anchoring*.rs` (`prune_before`), `telemetry*.rs` (`prune_idle_before`), `scheduler.rs` | `anchoring::tests::prune_*`, `telemetry::tests::prune_idle_before_*`, `chain_postgres::postgres_telemetry_*` |
| 22 | Bounded telemetry cardinality | `telemetry.rs` / `telemetry_pg.rs` (`MAX_TEXT_VALUES`) | `telemetry::tests::string_cardinality_is_capped` |
| 23 | Outbound timeouts + constant-time key compare | `netguard.rs` (`outbound_client`), `auth.rs` (`ct_eq`) | `auth::tests::*` (unit) |
| 24 | Config endpoints validated at startup (fail closed) | `netguard.rs` (`validate_endpoint`), `bootstrap.rs` | `bootstrap_validation::*` |
| 25 | Optional strict egress (host allowlist) for proxy + anchor | `netguard.rs` (`EgressGuard`), `authorize.rs` (`proxy`, `anchor_and_record`) | `netguard::tests::egress_guard_*`, `proxy_e2e::egress_allowlist_blocks_unapproved_provider_hosts` |
| 26 | Per-agent rate limits (blast-radius control) | `authorize.rs` (agent budget), `config.rs` (`AGENT_RATE_LIMIT_PER_MIN`) | `authorize_e2e::per_agent_rate_limit_throttles_only_the_noisy_agent` |
| 27 | Spoof-resistant client IP for public limits | `clientip.rs` (`TrustedProxies`), `http.rs` (`public_rate_limit`) | `clientip::tests::*`, `clientip_e2e::*` |
| 28 | Rate-limiter memory bounded without resetting live buckets | `ratelimit.rs` (`evict`) | `ratelimit::tests::capacity_eviction_*` |
| 29 | Credential TTL is clamped to a configured ceiling | `authorize.rs` (`max_ttl_seconds`), `issuers/github.rs` (`GITHUB_MAX_TTL_SECONDS`) | `authorize_e2e::credential_ttl_is_clamped_*`, `issuers_transport::github_ttl_is_capped_at_one_hour` |
| 30 | Per-resource budgets (provider blast radius) | `authorize.rs` (`tool_rate_limits`), `config.rs` (`TOOL_RATE_LIMITS`) | `authorize_e2e::tool_rate_limits_throttle_one_resource_only`, `config::tests::tool_rate_limits_parse_*` |
| 31 | Self-serve policy limits (TTL/budgets) that only tighten global caps | `policy.rs` (`PolicyLimits`), `authorize.rs` | `authorize_e2e::policy_limits_*`, `authorize_e2e::policy_agent_budget_*` |
| 32 | Signed, offline-verifiable audit export | `export.rs` (`ExportBundle::verify`, `verify_manifest`), `receipt.rs` (`sign_hash`/`recover_hash`), `http.rs` (`GET /v1/export/chain/:agent`) | `export::tests::*`, `authorize_e2e::signed_audit_export_*` |
| 33 | Bounded DB pools + statement timeout | `db.rs` (`pool_options`, `connect_pool`) | `chain_postgres::pools_apply_a_server_side_statement_timeout` |
| 34 | Constant-time admin token compare, handler panic isolation | `http.rs` (`keys_allowed`, `CatchPanicLayer`), `auth.rs` (`ct_eq`) | `auth::tests::*` |
| 35 | Tool-definition pinning; post-review redefinitions (rug pulls) denied | `tool_pins.rs`, `authorize.rs`, `http.rs` (`/v1/tools`) | `tool_pinning_refuses_silent_redefinitions`, `tool_pins_upsert_and_delete`, `tool_pins::tests::*` |
| 36 | Approved definition hash bound into the receipt | `receipt.rs` (`CallRef.tool_hash`), `authorize.rs` | `tool_pinning_refuses_silent_redefinitions` |
| 37 | Tool drift denials recorded in the tamper-evident ledger | `authorize.rs` (`tool.drift`), `key_events` | `tool_pinning_refuses_silent_redefinitions` |
| 38 | Policy changes audited (create/update/delete) with canonical digests | `http.rs` (`policy.changed`) | `policy_changes_are_audited_in_the_ledger` |
| 39 | Telemetry minimisation: PII/secret-like values redacted before storage and proposals | `telemetry.rs` (`looks_sensitive`, `REDACTED`) | `sensitive_values_are_redacted_before_storage`, `proposals_do_not_allowlist_the_redaction_marker` |
| 40 | Cross-language tool-definition hash parity | `tool_pins.rs`, `receipt-schema` (`toolDefinitionHash`) | `parity::fixture_tool_definition_hashes_match_expected` (Rust + TS) |
| 41 | Startup migrates every persistent store (single `AuthorizeService::migrate`) | `authorize.rs` (`migrate`), `main.rs`, `alerts.rs` (`AlertRouter::migrate`) | `migrations_postgres::startup_migrates_every_store` |
| 42 | Proxy outcomes are broker-observed and linked to their authorization after later actions | `authorize.rs` (`proxy_scoped`, `record_with_source`), `issuers/stripe.rs` (`bind`), `receipt.rs` (`authorizationReceiptId`, `outcome.source`) | `proxy_e2e::proxy_records_a_broker_observed_outcome`, `proxy_e2e::late_proxy_outcome_links_to_its_authorization`, `authorize_e2e::record_uses_indexed_lookups`, `chain_postgres::postgres_chain_*` |
| 43 | Authority transitions are signed and hash-linked | `authorize.rs` (`revoke`, `append_ledger_event`), `key_events.rs`, `http.rs` (`/v1/transitions`) | `authorize_e2e::revocation_appends_a_signed_authority_transition`, `authorize_e2e::http_step_up_*`, `key_events::tests::*` |
| 44 | Agent Receipts / W3C VC export is signed and standards-shaped | `packages/agent-receipts`, `apps/api` (`/v1/actions/:id/agent-receipt`) | `agent-receipts/test/*`, `apps/api/test/routes.test.ts` |
| 45 | KMS/HSM signing failure fails closed with no unsigned fallback | `signer.rs` (`HttpKmsSigner`), `receipt.rs` | `kms_signer::kms_server_error_does_not_sign`, `kms_signer::kms_malformed_signature_does_not_sign`, `kms_signer::kms_timeout_is_bounded_and_fails_closed` |
| 46 | Provider transport timeout is bounded and fail-closed | `proxy.rs`, `authorize.rs` (`proxy_scoped`) | `proxy_e2e::proxy_provider_timeout_fails_closed` |
| 47 | API plan limit blocks before broker/KMS work | `apps/api/src/routes.ts` (`/v1/authorize`) | `apps/api/test/routes.test.ts` (plan-limit assertion) |
| 48 | Delegating human is bound from the OIDC session; tokens are issuer/audience/tenant/agent scoped, single-use, and rotation-aware | `apps/api/src/authority.ts`, `apps/api/src/routes.ts`, `apps/broker/src/authority.rs`, `apps/broker/src/cache.rs` | `authority::tests::*`, `apps/api/test/authority.test.ts`, `apps/api/test/oidc.test.ts`, `authorize_e2e::verifies_hmac_authority_tokens` |
| 15 | Supply-chain / release hygiene | `.github/workflows/security.yml`, `sbom.yml`, `release.yml` | CI (gitleaks, cargo/npm audit, CycloneDX SBOM) |

## Fuzz coverage

Structural fuzzing (`apps/broker/fuzz`) targets the parsing/signing boundaries:
`canonical` (idempotence), `cel` (panic-freedom), `merkle` (proof soundness), `rlp` (length
prefixes), `receipt` (parse + hash + recover).

## How to run everything

```bash
cd apps/broker
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test cargo test
cargo clippy --all-targets -- -D warnings && cargo fmt --check

pnpm --filter @tessera-verify/receipt-schema test && pnpm --filter @tessera-verify/sdk-ts test
pnpm --filter @tessera-verify/verify test
pnpm --filter @tessera/mcp-adapter test
pnpm --filter @tessera-verify/langchain test
pnpm --filter @tessera/agent-receipts test
TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/tessera_test pnpm --filter @tessera/api test
pnpm --filter @tessera/portal test
cd contracts/receipts && forge test -vv
./examples/golden-path/run-local.sh
```

See [`audit-readiness.md`](audit-readiness.md) for the reviewer-facing summary.
