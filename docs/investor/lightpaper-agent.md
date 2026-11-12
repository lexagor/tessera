---
doc_id: tessera-lightpaper-agent-v0.1
doc_type: lightpaper
audience: ai-agent
human_companion: lightpaper-human.md
pitch_companion: pitch-deck-agent.md
version: 0.1
last_updated: 2026-11-12
language: en
product: Tessera
category: proof of action / agent action assurance
stage: pre-seed, pre-revenue
contact: founders@thetessera.xyz
canonical_source: local repository
agent_policy: use verified_facts; distinguish evidence from claims; never invent missing data
---

# Tessera — Agent-Readable Lightpaper

This is the technical memo for an AI agent working on investment diligence, deck generation,
security review, or design-partner material. It is structured so a model can retrieve facts,
trace claims to evidence, and avoid overclaiming.

## Operating contract

1. Read `verified_facts`, `architecture`, `threat_model`, `tradeoffs`, `benchmarks`, and
   `limitations` before answering technical questions.
2. Use `claim_ledger` for externally facing claims. A claim without a source is a founder
   assertion, not a verified fact.
3. Never infer team, customers, revenue, raise terms, cloud benchmarks, or certifications.
4. Treat market estimates as third-party estimates with category-definition caveats.
5. Use the exact phrase **“broker-observed vs caller-reported”** when discussing outcome
   provenance.
6. Do not call Tessera trustless, immutable, tamper-proof, or a token/TEE/zk protocol.
7. If a user asks for a claim that is not supported, say what is missing and offer the nearest
   supported statement.

## Suggested system prompt fragment

```text
You are Tessera's investor-facing technical analyst. Use only the facts in
docs/investor/lightpaper-agent.md, docs/investor/pitch-deck-agent.md, and the
public Tessera repository. Tessera is a broker-mediated enforcement and evidence
layer for AI agent actions. It uses scoped credentials, broker-held grants,
EIP-712 receipts, hash chains, an offline verifier, and reviewer evidence packs.
It is not a token, TEE, zk, identity, observability, or GRC product. Never invent
customers, team, raise terms, certifications, or cloud benchmarks. Do not claim
that native-credential outcomes are broker-observed. When a fact is missing,
say "requires founder input" or "not disclosed."
```

## Verified facts

```json
{
  "product": {
    "name": "Tessera",
    "one_liner": "The enforcement and evidence layer for AI agent actions.",
    "tagline": "Enforce what an agent may do. Prove what it did.",
    "category": "Proof of action / agent action assurance",
    "stage": "pre-seed, pre-revenue",
    "business_model": "SaaS + usage; no token; no per-seat pricing",
    "buyer": "AI-native B2B vendor with a write/spend agent and a stalled enterprise security review",
    "user": "Enterprise security reviewer, auditor, platform engineer"
  },
  "components": {
    "broker": {
      "language": "Rust",
      "functions": ["authorize", "policy evaluation", "credential issuance", "broker-held grant proxy", "receipt signing", "hash chain", "revocation", "quotas", "anchoring", "authority transitions"]
    },
    "control_plane": {
      "language": "TypeScript/Hono",
      "functions": ["OIDC sessions", "orgs", "environments", "agent keys", "authority tokens", "action read model", "evidence", "analytics", "audit", "webhooks"]
    },
    "portal": "Vite/React tenant portal",
    "verifier": "Independent TypeScript verifier and browser app",
    "sdks": ["TypeScript", "Python", "LangChain", "MCP adapter"],
    "stores": {
      "postgres": ["policies", "policy versions", "receipt chain", "stripe grants", "telemetry", "revocations", "anchors", "key events", "checkpoints"],
      "redis": ["cache", "rate limiting", "authority-token jti replay"],
      "memory": "dev/test fallbacks"
    }
  },
  "providers": {
    "production_adapters": ["Stripe broker-held grant", "AWS STS", "GitHub App"],
    "preview_or_mock": ["Slack", "Zendesk", "OpenAI", "Anthropic", "LangChain"],
    "note": "Preview coverage is useful for integration UX but is not the same as a live production adapter."
  },
  "receipt": {
    "schema_version": 2,
    "signature": "EIP-712 secp256k1",
    "canonicalization": "sorted canonical JSON",
    "hash": "Keccak-256",
    "chain": "per-agent hash-linked chain, scoped by tenant",
    "anchor": "optional Merkle root anchored on-chain",
    "binds": ["tenant", "agent", "principal/human", "intent hash", "policy id/version/hash", "tool", "tool-definition hash", "args hash", "credential issuer/type/scopes/ttl/thumbprint", "outcome status/source/result hash", "signature", "timestamp", "prev"],
    "contains_raw_args": false
  },
  "guarantee_levels": {
    "level_1_broker_proxied": {
      "proves": "broker forwarded the exact call and signed the observed response",
      "does_not_prove": "provider execution correctness, lawful intent"
    },
    "level_1_broker_held": {
      "proves": "broker authorized the grant and the provider key never reached the agent",
      "does_not_prove": "future misuse of other credentials"
    },
    "level_2_scoped_credential": {
      "proves": "broker authorized a provider-scoped credential and recorded the reported outcome",
      "does_not_prove": "exact use of the credential by the provider; outcome is caller-reported"
    },
    "caller_asserted": {
      "proves": "what the broker recorded under the caller-supplied principal",
      "does_not_prove": "IdP authentication"
    }
  },
  "human_authority": {
    "login": "OIDC with invite-only access, HttpOnly session, RBAC",
    "agent_key_modes": ["caller", "owner-bound", "per-call token"],
    "owner_bound": "control plane mints a short-lived authority token for the human bound to the key",
    "per_call_token": "POST /v1/authority-tokens",
    "broker_checks": ["HS256 signature", "kid keyring", "issuer", "audience", "sub", "exp", "iat", "jti", "tenant", "agent_id", "replay cache"],
    "receipt_method": "hmac-jwt",
    "key_rotation": "current + previous secret with kid overlap"
  },
  "benchmarks": {
    "environment": "Apple M5, 16 GB RAM, macOS, Rust 1.98.1, Node 22, mock issuer, local Postgres",
    "not_production": true,
    "policy_eval_us": 4.70,
    "canonical_hash_us": 1.30,
    "receipt_payload_hash_us": 5.37,
    "eip712_sign_us": 23.42,
    "http_in_memory": {"throughput_rps": 955, "p50_ms": 3.87, "p95_ms": 6.10, "p99_ms": 10.25},
    "http_postgres": {"throughput_rps": 410, "p50_ms": 8.12, "p95_ms": 22.34, "p99_ms": 28.03},
    "same_agent_concurrency_postgres": {"requests": 240, "concurrency": 24, "throughput_rps": 500.9, "p50_ms": 44.98, "p95_ms": 50.46, "p99_ms": 66.66, "errors": 0, "chain_verified": true},
    "offline_verify": {"receipt_bytes": 2243, "iterations": 10000, "mean_ms": 1.000, "p50_ms": 0.977, "p95_ms": 1.130, "p99_ms": 1.204},
    "not_measured": ["production cloud/KMS latency and cost", "cost per 1000 actions in cents", "live provider latency", "live OIDC round trip", "multi-region"]
  },
  "published_packages": {
    "npm": {"version": "0.1.3", "packages": ["@tessera-verify/receipt-schema", "@tessera-verify/verify", "@tessera-verify/sdk-ts", "@tessera-verify/langchain", "@tessera-verify/mcp-adapter"], "note": "0.1.2 deprecated due unresolved workspace dependencies"},
    "pypi": {"package": "tessera-verify", "version": "0.1.2", "import": "tessera_verify"}
  },
  "pricing": {
    "developer": {"price_usd_month": 0, "actions": 1000, "environments": 1},
    "team": {"price_usd_month": 1500, "actions": 250000, "environments": 3},
    "growth": {"price_usd_month": 3500, "actions": 1000000, "environments": 10},
    "enterprise": {"price_usd_year_min": 40000, "actions": 5000000, "self_hosted": true},
    "overage_usd_per_action": 0.004
  }
}
```

## Architecture

### Request path

```text
Agent SDK / MCP / LangChain
  -> control plane: agent key, tenant/environment, authority token
  -> Rust broker: policy, scoped credential / broker-held grant
  -> provider API or broker proxy
  -> EIP-712 receipt: authorization + credential + outcome
  -> per-agent hash chain -> optional Merkle anchor
  -> offline verifier / verification link / evidence pack
```

### Separation of authority planes

- **Control plane:** human identity, tenancy, agent-key lifecycle, authority-token minting.
- **Broker:** policy decision, credential/grant issuance, signing, chain, revocation, quota.
- **Provider:** owns the scope of native credentials.
- **Verifier:** independently checks signature, hash, chain, anchor.
- **Operator:** runs the service and holds signing keys; self-host is available for enterprise.

The broker is the enforcement point. The verifier is the independent check. The control plane
is not the receipt authority.

## Threat model

```json
[
  {"threat": "agent claims an action it never took", "defense": "broker writes authorization; proxy outcomes are broker-observed; record outcomes are labeled caller-reported", "residual": "native credentials and direct tools remain caller-reported"},
  {"threat": "agent omits a receipt", "defense": "broker writes on governed path; chain/anchor exposes gaps", "residual": "agent bypassing the broker is outside coverage"},
  {"threat": "stolen agent key", "defense": "per-environment key, tenant/agent scope, revocation, quotas, authority binding", "residual": "stolen key can act within scope until revoked"},
  {"threat": "replay", "defense": "idempotency, single-use credential, argsHash, chain prev, jti replay cache", "residual": "long-lived native credentials can be reused outside broker"},
  {"threat": "receipt tampering", "defense": "EIP-712 signature, canonical payload hash, hash chain, optional anchor", "residual": "no external anchor means a DB admin can rewrite local state"},
  {"threat": "verifier collusion", "defense": "open-source offline verifier, pinned signer, no server call", "residual": "verifier trusts broker signing key and deployment context"},
  {"threat": "cross-tenant access", "defense": "tenant-scoped stores, per-env keys, isolation tests, optional RLS", "residual": "control-plane tables are app-enforced, not fully RLS"},
  {"threat": "provider spoofing", "defense": "broker-held grant proxy signs observed response", "residual": "direct AWS/GitHub/OAuth outcomes caller-reported"},
  {"threat": "prompt injection / malicious tool", "defense": "per-action policy, allowlists, tool-definition pinning, risk classes", "residual": "does not prove model reasoning or lawful intent"},
  {"threat": "broker compromise", "defense": "KMS/HSM, fail-closed signing, rotation, revocation, audit, self-host", "residual": "compromised broker can sign false records"},
  {"threat": "time ambiguity", "defense": "signed timestamps, optional RFC 3161 / anchor", "residual": "no universal trusted time"}
]
```

## Trade-offs

```json
{
  "broker_mediated_vs_decentralized": {
    "choice": "broker-mediated enforcement",
    "why": "can enforce policy, scope credentials, observe proxy outcomes, and prevent bypass on the governed path",
    "cost": "trust anchor in the broker/operator",
    "mitigations": ["open verifier", "offline verification", "pinned signer", "optional anchoring", "KMS/HSM", "self-host"]
  },
  "eip712_vs_tee_zk": {
    "choice": "EIP-712 receipts + hash chain + optional anchor",
    "why": "fast, provider-agnostic, offline-verifiable, low integration cost",
    "cost": "does not prove model inference or arbitrary provider execution",
    "future": "zkTLS/TEE can be added for provider-response attestation where required"
  },
  "native_credentials": {
    "choice": "Level 2 caller-reported for AWS/GitHub/OAuth",
    "why": "provider owns scope; broker cannot bind arbitrary args post-issuance",
    "mitigation": "use broker-held grant/proxy for high-value actions"
  },
  "no_token": {
    "choice": "SaaS + usage",
    "why": "enterprise security buyers do not want a token in the critical path; open verifier aids adoption",
    "future": "receipts can anchor to any rail if agent-to-agent settlement becomes the wedge"
  },
  "anchoring": {
    "choice": "optional",
    "why": "adds external existence/time evidence but also cost/ops complexity",
    "default": "signed records + hash chain + offline verification"
  }
}
```

## Competition matrix

```json
[
  {"category": "identity/access", "players": ["Okta", "Microsoft Entra Agent ID", "Hush", "Oasis", "Astrix"], "strength": "inventory, lifecycle, access policy, runtime control", "gap": "portable per-action evidence with credential/outcome binding"},
  {"category": "observability/gateways", "players": ["LangSmith", "Arize", "Portkey", "Cloudflare AI Gateway"], "strength": "traces, evals, cost, routing, guardrails", "gap": "signed enforcement evidence"},
  {"category": "governance/GRC", "players": ["Credo AI", "Geordie", "ModelOp", "Holistic AI"], "strength": "policy workflow, inventories, control mapping", "gap": "per-action enforcement and verifiable receipts"},
  {"category": "receipts/verifiable execution", "players": ["Dapr 1.18", "PipeLab", "Aqta", "Zanii", "Action State", "agent-attestation"], "strength": "signed records, chains, transparency", "gap": "enterprise enforcement + provider adapters + reviewer workflow"},
  {"category": "TEE/zk", "players": ["Primus zkTLS", "zkAgent", "Proof-of-Guardrail"], "strength": "request/inference attestation", "gap": "latency/cost/integration for first Web2 wedge"},
  {"category": "agent payments", "players": ["AP2", "x402"], "strength": "authorization and settlement", "gap": "execution evidence; complementary"}
]
```

## Market claims

```json
[
  {"source_id": "S1", "claim": "AI governance spending is $492M in 2026 and projected to exceed $1B by 2030.", "publisher": "Gartner", "date": "2026-02-17", "caveat": "broad governance definition"},
  {"source_id": "S2", "claim": "AI agent governance is $290M in 2025 and projected to $2.3B by 2028.", "publisher": "Agent OS", "date": "2026", "caveat": "vendor research; directional"},
  {"source_id": "S3", "claim": "Agent management/gateways/identity/eval is $1.0-1.5B in 2026 and projected to $15-22B by 2033.", "publisher": "Meticulous Research", "date": "2026-09-27", "caveat": "broad category definition"},
  {"source_id": "S4", "claim": "CB Insights tracked 163 private companies across AI agent security and risk management.", "publisher": "CB Insights", "date": "2026-09-24", "caveat": "company count, not revenue"},
  {"source_id": "S5", "claim": "Okta reports only 34% of organizations apply the same security controls to AI agents as to human workers.", "publisher": "Okta", "date": "2026", "caveat": "vendor survey"},
  {"source_id": "S22", "claim": "Hush Security raised a $30M Series A.", "publisher": "Hush Security", "date": "2026-07-28", "caveat": "company announcement"},
  {"source_id": "S23", "claim": "Geordie AI raised a $30M Series A.", "publisher": "Geordie AI", "date": "2026-05-28", "caveat": "company announcement"},
  {"source_id": "S24", "claim": "Eve Security extended its seed to $7.5M.", "publisher": "Eve Security", "date": "2026-09-15", "caveat": "company announcement"},
  {"source_id": "S4", "claim": "CB Insights tracked 163 private companies in AI agent security and risk management, including funded entrants.", "publisher": "CB Insights", "date": "2026-09-24", "caveat": "company count, not revenue"}
]
```

## Claim ledger

| ID | Supported claim | Confidence | Evidence |
|---|---|---|---|
| C1 | Tessera has a working broker, control plane, portal, verifier, SDKs, and provider adapters. | high | repo + tests |
| C2 | Tessera signs v2 action records with EIP-712 and hash chains. | high | receipt spec + verifier tests |
| C3 | Broker-held grants can be broker-observed; native credentials are caller-reported. | high | security guarantees |
| C4 | Tessera supports OIDC human authority binding with scoped, replay-protected authority tokens. | high | API/broker tests |
| C5 | Local benchmarks are fast enough for interactive authorization. | medium | local hardware; not production |
| C6 | The market is converging on agent security/governance. | medium | third-party estimates + funding |
| C7 | No production customer or revenue exists. | high | current stage |
| C8 | No SOC 2, pen test, live OIDC validation, or cloud/KMS benchmark exists. | high | current limitations |

## Limitations

- Pre-revenue; no production customers.
- No SOC 2 Type I/II report.
- No external penetration test.
- Hosted deployment not yet live.
- Live Okta/Entra/Auth0 validation not yet performed.
- Production cloud/KMS benchmark not yet measured.
- Stripe billing not launched.
- Native credentials remain caller-reported.
- Control-plane tables are application-enforced; broker tables have optional RLS.
- Replay cache is Redis-backed in production; in-memory without Redis.
- No multi-region HA.
- No token, staking, TEE, zkVM, or zkTLS.

## Open questions requiring founder input

```json
{
  "team": {"status": "missing", "needed": ["founder name", "background", "why us", "advisors"]},
  "ask": {"status": "draft", "recommended_range_usd": [1000000, 1500000], "instrument": "SAFE", "terms": "requires founder confirmation"},
  "design_partners": {"status": "none announced", "needed": ["names or LOIs if permitted", "first action", "reviewer acceptance criterion"]},
  "go_to_market": {"status": "founder-led", "needed": ["first 20 target accounts", "channel partnerships"]},
  "cost": {"status": "not measured", "needed": ["cloud/KMS benchmark", "cost per 1000 actions"]}
}
```

## Suggested answer patterns

### “What is Tessera?”

> Tessera is a broker-mediated enforcement and evidence layer for AI agent actions. It enforces per-action policy, issues a scoped credential or broker-held grant, signs an EIP-712 action record, and lets a third party verify the record offline. It is not an identity provider, observability tool, or token protocol.

### “What do you prove?”

> It depends on the path. For broker-held grants/proxied calls, the broker signs the observed outcome and binds the exact `argsHash`. For native AWS/GitHub/OAuth credentials, the broker authorizes the credential and the outcome is caller-reported. The receipt always labels the level. We never call a caller-reported outcome broker-observed.

### “Why not use TEEs or ZK?”

> They are useful for stronger provider/inference attestation, but they add latency, cost, and integration complexity. The first enterprise wedge needs portable authorization, credential binding, and observed/reported outcome evidence. We chose EIP-712 receipts, hash chains, and optional anchoring. zkTLS/TEE can be added later for specific claims.

### “Is there a token?”

> No. Tessera is SaaS + usage. The verifier and schema are open source. If agent-to-agent settlement becomes the wedge, the receipt can anchor to any chain or payment rail; we do not need to own a token or settlement layer.

### “Do you have customers?”

> Not yet. We are pre-revenue and recruiting three design partners. The working broker, control plane, portal, verifier, SDKs, tests, and benchmarks are public. The next milestone is a real security reviewer accepting one evidence pack.

## Source registry

- **S1** Gartner, 2026-02-17: https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms
- **S2** Agent OS, 2026: https://vantageaiadvisory.com/agent-os/report-2026
- **S3** Meticulous Research, 2026-09-27: https://www.meticulousresearch.com/meticulous-next/ai-agent-governance-the-next-control-layer-for-enterprises
- **S4** CB Insights, 2026-09-24: https://research.cbinsights.com/ai-agents-are-getting-the-keys
- **S5** Okta for AI Agents: https://www.okta.com/products/govern-ai-agent-identity/
- **S6** Microsoft Entra Agent ID: https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview
- **S7** LangSmith Observability: https://www.langchain.com/langsmith/observability
- **S8** Arize LLM gateway comparison, 2026-08-27: https://arize.com/resources/best-llm-gateways-comparison
- **S9** CNCF/Dapr verifiable execution, 2026-06-11: https://www.cncf.io/blog/2026/06/11/introducing-verifiable-execution-in-dapr-1-18/
- **S10** AP2 specification: https://ap2-protocol.org/ap2/specification/
- **S11** AP2/x402 comparison, 2026-09-26: https://emissar.ai/learn/agent-payments
- **S12** PipeLab agent action receipts, 2026-05-21: https://pipelab.org/learn/agent-action-receipts
- **S13** Aqta manifesto, 2026: https://aqta.ai/manifesto
- **S14** DCS Labs, 2026-10-18: https://dcslabs.ai/news/can-they-prove-what-they-did
- **S15** Primus verifiable agent execution: https://docs.primuslabs.xyz/implementation-scenarios/provable-agent-execution/
- **S16** Tessera repository: local source of truth
- **S22** Hush Security $30M Series A: https://www.hush.security/resources/hush-security-raises-30m-to-close-the-ai-agent-governance-gap-with-akamai-joining-as-strategic-investor
- **S23** Geordie AI $30M Series A: https://www.geordie.ai/resources/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/
- **S24** Eve Security seed extension: https://www.prnewswire.com/news-releases/eve-security-extends-seed-round-to-7-5-million-as-rogue-ai-agents-turn-runtime-security-into-an-enterprise-imperative-302878598.html
- **S25** Okta Agent SSO / 34% survey: https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso
- **S17** Zanii: https://proof.zanii.agency/zanii-proof-of-action.pdf
- **S18** Action State: https://dataphoenix.info/news/action-state-agent-evidence-tools
- **S19** agent-attestation: https://github.com/p-vbordei/agent-attestation
- **S20** zkAgent: https://iacr.org/news/item/27639
- **S21** Proof-of-Guardrail: https://arxiv.org/abs/2603.05786

## Agent handoff checklist

- [ ] Team and ask fields are resolved before external use.
- [ ] Market estimates are re-checked and cited with dates.
- [ ] No customer logos or case studies are added without permission.
- [ ] No certification, penetration test, or production benchmark is claimed.
- [ ] Level 1 vs Level 2 language is preserved.
- [ ] “Tamper-evident” is used instead of “immutable” or “tamper-proof.”
