# Tessera

> Proof of action for AI agents.

[thetessera.xyz](https://thetessera.xyz) · [docs](https://thetessera.xyz/docs/)

Tessera enforces what an agent may do, then binds the agent, the delegating human, the intent,
the policy, the tool definition, the credential, and the outcome into a signed action record.
A third party can verify that record offline — without trusting Tessera, the agent vendor, or
either party's logs.

```
Agent runtime / SDK / MCP adapter
        │  agent API key + exact tool call + args
        ▼
Control plane (orgs, sessions, environments, agent keys, action read model)
        │  environment-scoped broker credential
        ▼
Rust broker (authorize → CEL policy → scoped credential / broker-held grant)
        │                                   │
        ▼                                   ▼
Provider API / proxy                 EIP-712 signed receipt
                                            │
                                            ▼
                                  Hash-linked chain + anchors
                                            │
                                            ▼
                              Public verifier / evidence pack
```

Status: **live at `thetessera.xyz` with Auth0 login; billing is disabled and design partners are the next rollout step.** The
Rust broker ships the authorize → broker → receipt → chain → verify loop with provider
adapters, broker-observed proxy outcomes, authority transitions, revocation, KMS/HSM bridge
signing, quotas, and 300+ tests. The control plane (`apps/api`) and tenant portal (`apps/portal`)
cover OIDC sessions, environments, agent keys, actions, integrations, evidence packs, reviewer
reports and share links, verification links, authority transitions, analytics, usage, and audit.
Agent Receipts v0.5 specification export, LangChain tool wrapping, and the MCP adapter are
implemented. Agent keys can be owner-bound to an OIDC-authenticated human or use a short-lived
per-call authority token. The broker validates issuer/audience, tenant/agent scope, expiry, and
single-use `jti`, supports `kid` key rotation, and records `verificationMethod: hmac-jwt`.
Auth0 is live; billing is intentionally disabled and design-partner evidence is the next distribution step.
Pre-revenue; recruiting design partners.

## Packages

Registry state:

- `@tessera-verify/receipt-schema`, `verify`, `sdk-ts`, `langchain`, and `mcp-adapter` are live
  on npm at **0.1.3**.
- npm **0.1.2** is deprecated because it was published with unresolved `workspace:*`
  dependencies. Install `0.1.3` or later.
- `tessera-verify` (Python, import `tessera_verify`) is live on PyPI at **0.1.2**:

```bash
pip install tessera-verify
```

```bash
npm install @tessera-verify/receipt-schema
npm install @tessera-verify/verify
npm install @tessera-verify/sdk-ts
npm install @tessera-verify/langchain
```

- `@tessera-verify/receipt-schema` — receipt types, canonical hashing, EIP-712 definitions
- `@tessera-verify/verify` — independent verifier and `tessera-verify` CLI
- `@tessera-verify/sdk-ts` — agent SDK
- `@tessera-verify/langchain` — LangChain tool wrapper

## Performance

Measured on an Apple M5 development machine with a mock issuer (not a production benchmark):

- policy evaluation + CEL: **4.70 µs**;
- EIP-712 receipt signing: **23.42 µs**;
- HTTP authorize p50/p95/p99: **3.87 / 6.10 / 10.25 ms** (in-memory) and **8.12 / 22.34 /
  28.03 ms** (Postgres);
- offline v2 verification: **~1.00 ms**, 2,243-byte receipt.

See [`BENCHMARKS.md`](BENCHMARKS.md) for hardware, commands, and caveats.

## Why

- Agents are moving from read-only to **write + spend** authority.
- Static API keys in agent runtimes are a top exfiltration vector.
- Traditional IAM answers "who is the agent" and "what app can it reach." It does not bind the
  exact tool call, the human authority behind it, and the outcome into portable evidence.
- Enterprise security reviews stall agent deals because vendors cannot prove what an agent did
  on whose authority, and that the record was not altered.

## What the broker does

1. **Authorize** the declared intent against policy (deterministic constraints + CEL).
2. **Broker** a single-use, `argsHash`-bound credential — or a broker-held grant the agent
   never sees.
3. **Bind** the principal authority, policy hash, tool definition, credential thumbprint, and
   outcome into a v2 action record.
4. **Receipt** the decision and outcome as an EIP-712-signed artifact.
5. **Chain** records per agent and optionally anchor Merkle roots.
6. **Verify** independently, and **revoke** natively where the provider allows.

## Quickstart

Run the broker (in-memory stores, demo mode):

```bash
cd apps/broker
BROKER_PORT=8787 TESSERA_DEMO_ALLOW=1 cargo run
```

Call it with the SDK:

```bash
pnpm install
cd examples/governed-agent
TESSERA_API_KEY=tsk_demo_local pnpm start
```

Full loop against real providers + a real chain, one command (mock Stripe + anvil + broker):

```bash
./examples/golden-path/run-local.sh
```

Verify a record offline (TypeScript verifier):

```bash
npm install @tessera-verify/verify
npx tessera-verify receipt.json
# or run the local verification page:
pnpm --filter @tessera/verify-app dev
```

Full control plane + portal + verifier (local dev auth, demo broker mode):

```bash
docker compose -f infra/docker/docker-compose.yml up --build
# portal:   http://localhost:8080
# verifier: http://localhost:8080/verify/
# site:     http://localhost:8081/docs/
```

With Postgres/Redis (production stores):

```bash
docker compose -f infra/docker/docker-compose.yml up
```

Kubernetes: `infra/k8s/helm/tessera` (see its README).

## Demo

See [`docs/demo-script.md`](docs/demo-script.md) for the 45-second recording script covering
the policy decision, human authority binding, denial, verification, tamper detection, and
evidence pack.

## Repository layout

```
apps/broker        Rust service: authorize + issue ephemeral credentials + signed records
apps/api           TypeScript control plane (Hono): OIDC, tenancy, actions, evidence
apps/portal        Vite + React tenant portal
apps/verify        Public verifier: links, offline bundles, tamper demo
apps/site          Static landing page + docs site
packages/sdk-ts    Drop-in TS SDK (wrap Stripe/GitHub/Slack/MCP clients)
packages/sdk-py    Python SDK
packages/verifier  Independent receipt verifier (TypeScript)
packages/ui        Shared portal/verifier design tokens and primitives
packages/core-policy  Shared policy model (CEL)
packages/receipt-schema  Receipt JSON schema + EIP-712 types
packages/issuers   Provider adapters (AWS STS, GitHub App, Stripe, OAuth2)
packages/mcp-adapter  MCP middleware
packages/langchain  LangChain tool wrapper
packages/agent-receipts  Agent Receipts v0.5.0 / W3C VC export
contracts/receipts Foundry anchor contract
infra/docker       VPS-ready compose
examples/          Runnable agent examples, including Vercel AI SDK and PydanticAI
docs/              Architecture, threat model, receipt spec, controls, RFCs
```

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — release history
- [`BENCHMARKS.md`](BENCHMARKS.md) — reproducible broker, HTTP, concurrency, and verifier benchmarks
- [`docs/benchmarks-cloud.md`](docs/benchmarks-cloud.md) — cloud/KMS benchmark runbook
- [`examples/vercel-ai-agent`](examples/vercel-ai-agent) — Vercel AI SDK tool wrapper example
- [`examples/pydantic-ai-agent`](examples/pydantic-ai-agent) — PydanticAI tool wrapper example
- [`docs/proof-of-action.md`](docs/proof-of-action.md) — positioning, ICP, objections, and 90-day plan
- [`docs/receipt-spec.md`](docs/receipt-spec.md) — receipt schema and chain
- [`docs/architecture.md`](docs/architecture.md) — system design
- [`docs/threat-model.md`](docs/threat-model.md) — threats and controls
- [`docs/controls-matrix.md`](docs/controls-matrix.md) — invariant → code → test map
- [`docs/audit-readiness.md`](docs/audit-readiness.md) — scope, invariants, how to reproduce
- [`docs/audit-brief.md`](docs/audit-brief.md) — submission-ready audit brief
- [`docs/security-guarantees.md`](docs/security-guarantees.md) — provider-by-provider enforcement and evidence guarantees
- [`docs/trust-center.md`](docs/trust-center.md) — security posture and data handling
- [`docs/webhooks.md`](docs/webhooks.md) — signed event delivery and retries
- [`docs/authority-transitions.md`](docs/authority-transitions.md) — revocations, rotations, and step-ups
- [`docs/integrations.md`](docs/integrations.md) — provider coverage, credential posture, and setup tests
- [`docs/analytics.md`](docs/analytics.md) — analytics definitions, alerts, search, and shortcuts
- [`docs/evidence-packs.md`](docs/evidence-packs.md) — framework coverage, reviewer reports, and share links
- [`docs/distribution.md`](docs/distribution.md) — public repo, npm packages, and verifier rollout
- [`docs/demo-script.md`](docs/demo-script.md) — product demo recording sequence
- [`docs/deploy-thetessera-xyz.md`](docs/deploy-thetessera-xyz.md) — site/app/verifier deployment checklist
- [`docs/pricing.md`](docs/pricing.md) — billing status and current plan limits
- [`docs/billing.md`](docs/billing.md) — internal billing integration notes
- [`docs/rls.md`](docs/rls.md) — broker row-level security and automated check
- [`docs/control-plane-rls.md`](docs/control-plane-rls.md) — control-plane RLS design
- [`docs/data-lifecycle.md`](docs/data-lifecycle.md) — export, deletion request, retention, and purge
- [`docs/staging-rollback.md`](docs/staging-rollback.md) — staging and release rollback runbook
- [`docs/load-testing.md`](docs/load-testing.md) — staging load harness
- [`docs/dependency-updates.md`](docs/dependency-updates.md) — Renovate policy
- [`docs/privacy.md`](docs/privacy.md), [`docs/terms.md`](docs/terms.md), [`docs/dpa.md`](docs/dpa.md), [`docs/subprocessors.md`](docs/subprocessors.md) — legal and data-processing terms
- [`docs/security-sla.md`](docs/security-sla.md) — security contact and response targets
- [`docs/auth0-production.md`](docs/auth0-production.md) — custom domain and email-provider runbook
- [`docs/kms-production.md`](docs/kms-production.md) — KMS/HSM migration runbook
- [`docs/edge-and-dns.md`](docs/edge-and-dns.md) — WAF/DDoS options and DNS decision
- [`docs/soc2-readiness.md`](docs/soc2-readiness.md) — SOC 2 readiness mapping and evidence cadence
- [`docs/security-policies.md`](docs/security-policies.md) — draft security policy set for readiness
- [`docs/pentest-scope.md`](docs/pentest-scope.md) — external penetration-test scope and rules
- [`docs/incident-response.md`](docs/incident-response.md) — incident severity, roles, and runbook
- [`docs/support-sla.md`](docs/support-sla.md) — support channels and response targets
- [`docs/multi-az-dr.md`](docs/multi-az-dr.md) — HA/DR target and failover drill
- [`docs/enterprise-sso.md`](docs/enterprise-sso.md) — Auth0 Organizations and SCIM model
- [`docs/scim.md`](docs/scim.md) — SCIM Users API and token setup
- [`docs/kms-benchmark.md`](docs/kms-benchmark.md) — KMS/HSM benchmark harness
- [`docs/independent-security-review.md`](docs/independent-security-review.md) — external review package
- [`docs/reviewer-acceptance.md`](docs/reviewer-acceptance.md) — reviewer acceptance evidence template
- [`docs/golden-path.md`](docs/golden-path.md) — full loop against real providers
- [`docs/rfcs/0001-action-broker.md`](docs/rfcs/0001-action-broker.md) — action broker spec
- [`docs/governance-plane-plan.md`](docs/governance-plane-plan.md) — superseded historical plan

## License

Apache-2.0. See [`LICENSE`](LICENSE).
