# Security Guarantees

This page is the source of truth for what Tessera enforces, observes, and proves. It is
deliberately narrower than marketing language: every row states what the broker can enforce at
the provider boundary, what it can only record, and what it cannot prove.

## Guarantee matrix

| Provider / path | Credential | Argument-bound? | Single-use? | Outcome source | Revocation | What the receipt proves |
|---|---|---:|---:|---|---|---|
| Stripe broker-held grant | Broker-held restricted key; agent gets a grant id | **Yes** — proxy re-checks `argsHash` and grant expiry | **Yes** | **Broker-observed** | Broker invalidates the grant; the provider key is never exposed | Policy allowed this exact call, the broker proxied it, and the linked outcome was observed |
| Stripe direct API | Not supported by the broker path | — | — | — | — | — |
| AWS STS | Short-lived STS session scoped by session policy and TTL | **No** — provider does not bind arbitrary tool arguments | **No** | Caller-reported | New sessions can be denied; an existing STS session remains valid until expiry | The broker authorized issuance and recorded the caller-reported outcome; it does not prove the exact post-issuance arguments |
| GitHub App installation token | Installation token scoped to repos/permissions and TTL | **No** — provider does not bind arbitrary tool arguments | **No** | Caller-reported | Native provider revocation | The broker authorized issuance and recorded the caller-reported outcome; the token could be reused within its scope until expiry/revocation |
| OAuth2 / bearer credential | Provider-scoped token | **No** | Provider-dependent | Caller-reported | Provider-dependent | The broker authorized issuance and recorded the caller-reported outcome |
| MCP adapter, direct bearer | Provider token injected by the adapter | **No** | Provider-dependent | Caller-reported | Provider-dependent | The exact `authorize` request and the self-reported outcome are signed; execution is not observed |
| LangChain wrapper, direct bearer | Provider token injected by the wrapper | **No** | Provider-dependent | Caller-reported | Provider-dependent | The exact `authorize` request and the self-reported outcome are signed; execution is not observed |
| `/v1/proxy` (broker-held grant) | Broker-held provider secret | **Yes** | **Yes** | **Broker-observed** | Broker grant invalidation | The broker forwarded one scoped request and signed the observed response |
| `/v1/record` | None | **No** — the agent reports the result hash/status | — | Caller-reported | — | The agent reported an outcome bound to the authorization receipt |
| Receipt chain | EIP-712 signed records | Hash-bound to the recorded fields | — | Mixed | — | Records are tamper-evident from the point of the signed/anchored evidence; they are not an immutable database |
| Anchored Merkle root | External chain transaction | — | — | — | — | A batch existed with a given root by the anchor time; it does not prove semantic correctness of the provider call |
| Control plane | Org/environment scoping | — | — | — | Session/API-key revocation | The requested tenant scope was authorized by the API; control-plane tables are not currently under Postgres RLS |

## Enforcement levels

Use these labels in reviews and demos. They describe the evidence path, not a certification.

- **Level 1 — broker-proxied / argument-bound / broker-observed:** the broker holds the provider
  credential, re-checks the exact `argsHash` at execution time, forwards one request, and signs
  the observed response. Example: Stripe broker-held grant via `/v1/proxy`.
- **Level 2 — scoped credential / caller-reported:** the broker authorizes issuance of a
  provider-scoped credential and signs the authorization plus the agent-reported outcome. It
  does not observe the provider call or prove the exact argument use. Examples: AWS STS, GitHub
  installation tokens, OAuth bearer credentials, LangChain and MCP direct-bearer paths.
- **Caller-asserted authority:** the principal in the receipt is supplied by the caller rather
  than derived from a verified authority token. The record proves what the broker recorded, not
  who delegated it. With `TESSERA_AUTHORITY_HMAC_SECRET` configured, owner-bound agent keys
  produce `verificationMethod: "hmac-jwt"` records instead.

## Important nuances

- **Argument binding is a provider path property, not a property of every credential.** Only the
  broker-held grant/proxy path re-checks the exact argument hash at execution time. Native AWS,
  GitHub, and OAuth bearer credentials are scoped by the provider, not by the tool arguments.
- **Broker-observed is stronger than caller-reported.** A proxied response can be signed by the
  broker. A direct credential outcome is only what the agent reported.
- **A receipt proves what was signed.** It does not prove the provider executed correctly, that
  the agent did not leak a credential, or that the underlying business intent was lawful.
- **Hash chains are tamper-evident, not tamper-proof.** Anchors, exports, and independent
  verification make retroactive edits detectable; a database administrator can still rewrite
  local state if no external evidence exists.
- **Control-plane isolation is currently application-enforced.** The broker has Postgres RLS
  for broker tables. The API enforces `org_id`/`environment_id` scoping in every query and is
  covered by cross-tenant tests; control-plane tables are not under RLS today.

## Failure behavior

- KMS/HSM signing failures are **fail-closed**: receipt and anchor signing return an error; no
  unsigned fallback record is written.
- Provider transport timeouts are bounded and return structured issuer errors. The proxy records
  a broker-observed failure outcome when the authorization was already bound to a grant.
- API plan limits return `402 plan_limit_exceeded` before the broker is called.
- Circuit breakers are not implemented yet; the current boundary is connect/total request
  timeouts plus fail-closed handling.

## Code and test anchors

- Broker-held Stripe grant: `apps/broker/src/issuers/stripe.rs`, `apps/broker/src/proxy.rs`, `apps/broker/tests/proxy_e2e.rs`
- Proxy outcome provenance: `apps/broker/src/authorize.rs` (`proxy_scoped`, `record_proxy_outcome`)
- Idempotency and request binding: `apps/broker/src/http.rs`, `apps/broker/tests/authorize_e2e.rs`
- Revocation: `apps/broker/src/revocation.rs`, `apps/broker/src/authorize.rs`, `apps/broker/tests/authorize_e2e.rs`
- Receipt integrity: `apps/broker/src/receipt.rs`, `apps/broker/tests/verify.rs`, `packages/verifier`
- Human authority binding: `apps/api/src/authority.ts`, `apps/api/src/routes.ts`,
  `apps/api/test/authority.test.ts`, `apps/api/test/oidc.test.ts`, `apps/broker/tests/authorize_e2e.rs`
- Cross-tenant API isolation: `apps/api/test/tenant-isolation.test.ts` (actions, reviews, evidence, keys, integrations, analytics, notifications, search)
- Broker RLS: `infra/sql/rls.sql`, `apps/broker/tests/rls_postgres.rs`
- KMS/HSM bridge: `apps/broker/src/signer.rs`, `apps/broker/tests/kms_signer.rs`

## Sales-safe wording

> Tessera enforces per-action policy and produces signed, independently verifiable records. For
> broker-held grants, Tessera observes the provider response and binds it to the exact
> authorized arguments. For native AWS, GitHub, and OAuth bearer credentials, Tessera binds the
> authorization and the reported outcome, but the provider — not Tessera — scopes the credential.
