# Tessera

> Proof of action for AI agents.

Tessera enforces what an agent may do, then binds the agent, the delegating human, the intent,
the policy, the tool definition, the credential, and the outcome into a signed action record.
A third party can verify that record offline — without trusting Tessera, the agent vendor, or
either party's logs.

Status: **broker + control plane + portal implemented; hosted hardening in progress.** The
Rust broker ships the authorize → broker → receipt → chain → verify loop with provider
adapters, broker-observed proxy outcomes, authority transitions, revocation, KMS signing,
quotas, and 300+ tests. The control plane (`apps/api`) and tenant portal (`apps/portal`) cover
OIDC sessions, environments, agent keys, actions, evidence, verification links, authority
transitions, usage, and audit. Agent Receipts v0.5.0 export, LangChain tool wrapping, OIDC
provider credentials, Stripe billing, and public package/domain rollout are the remaining
hosted pieces. Pre-revenue; recruiting design partners.

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
```

With Postgres/Redis (production stores):

```bash
docker compose -f infra/docker/docker-compose.yml up
```

Kubernetes: `infra/k8s/helm/tessera` (see its README).

## Repository layout

```
apps/broker        Rust service: authorize + issue ephemeral credentials + signed records
apps/api           TypeScript control plane (Hono): OIDC, tenancy, actions, evidence
apps/portal        Vite + React tenant portal
apps/dashboard     Legacy dev console (kept until portal parity)
apps/verify        Public verifier: links, offline bundles
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
examples/          Runnable agent examples
docs/              Architecture, threat model, receipt spec, controls, RFCs
```

## Documentation

- [`docs/proof-of-action.md`](docs/proof-of-action.md) — positioning, ICP, pricing, objections
- [`docs/receipt-spec.md`](docs/receipt-spec.md) — receipt schema and chain
- [`docs/architecture.md`](docs/architecture.md) — system design
- [`docs/threat-model.md`](docs/threat-model.md) — threats and controls
- [`docs/controls-matrix.md`](docs/controls-matrix.md) — invariant → code → test map
- [`docs/audit-readiness.md`](docs/audit-readiness.md) — scope, invariants, how to reproduce
- [`docs/audit-brief.md`](docs/audit-brief.md) — submission-ready audit brief
- [`docs/trust-center.md`](docs/trust-center.md) — security posture and data handling
- [`docs/webhooks.md`](docs/webhooks.md) — signed event delivery and retries
- [`docs/authority-transitions.md`](docs/authority-transitions.md) — revocations, rotations, and step-ups
- [`docs/distribution.md`](docs/distribution.md) — public repo, npm packages, and verifier rollout
- [`docs/billing.md`](docs/billing.md) — plans, usage limits, and Stripe billing
- [`docs/rls.md`](docs/rls.md) — Postgres row-level security (defense in depth)
- [`docs/golden-path.md`](docs/golden-path.md) — full loop against real providers
- [`docs/rfcs/0001-action-broker.md`](docs/rfcs/0001-action-broker.md) — action broker spec
- [`docs/governance-plane-plan.md`](docs/governance-plane-plan.md) — superseded historical plan

## License

Apache-2.0. See [`LICENSE`](LICENSE).
