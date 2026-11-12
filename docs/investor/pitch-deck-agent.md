---
doc_id: tessera-pitch-deck-agent-v0.1
doc_type: pitch-deck
audience: ai-agent
human_companion: pitch-deck-human.md
lightpaper_companion: lightpaper-agent.md
version: 0.1
last_updated: 2026-11-12
language: en
product: Tessera
category: proof of action / agent action assurance
stage: pre-seed, pre-revenue
contact: founders@thetessera.xyz
canonical_source: local repository
agent_policy: use only verified_facts; never invent team, ask, customers, certifications, or cloud benchmarks
---

# Tessera — Agent-Readable Pitch Deck

This file is the machine-oriented version of the Tessera investor deck. It is designed for a
coding or research agent to ingest, query, and use when drafting investor emails, diligence
responses, technical summaries, or follow-up documents.

## Operating contract

1. Prefer the structured facts in the JSON block below over prose.
2. Cite `source_id` values when making market or competitive claims.
3. If a requested fact is not in `verified_facts`, say **“not disclosed”** or **“requires founder input.”**
4. Never upgrade a limitation into a feature.
5. Never describe Tessera as trustless, immutable, tamper-proof, a token protocol, a TEE, or a zk system.
6. Use **tamper-evident**, **independently verifiable**, **evidence mapping**, and
   **broker-observed vs caller-reported** precisely.
7. Market estimates vary by category definition. Present ranges and cite the source.

## Suggested system prompt fragment

```text
You are Tessera's investor-facing technical analyst. Use only facts in
docs/investor/pitch-deck-agent.md and docs/investor/lightpaper-agent.md. When a
fact is missing, say "not disclosed" rather than inferring it. Tessera is a
broker-mediated enforcement + evidence layer for AI agent actions. It uses
EIP-712 receipts, hash chains, scoped credentials, broker-held grants, and an
offline verifier. It is not a token, TEE, zk, identity, observability, or GRC
product. Never claim SOC 2, a completed pen test, live customers, production
cloud benchmarks, or automatic settlement. For team and raise terms, ask the
founder; do not invent them.
```

## Canonical deck object

```json
{
  "product": {
    "name": "Tessera",
    "one_liner": "The enforcement and evidence layer for AI agent actions.",
    "tagline": "Enforce what an agent may do. Prove what it did.",
    "category": "Proof of action / agent action assurance",
    "buyer": "CTO, Head of Security, or Head of Platform at an AI-native B2B vendor with a write/spend agent and a stalled enterprise security review.",
    "user": "Enterprise security reviewer, auditor, or platform engineer.",
    "wedge": "One consequential write/spend action, one reviewer, one evidence pack.",
    "not": [
      "identity provider",
      "LLM firewall",
      "observability/evaluation platform",
      "GRC certification platform",
      "token/staking protocol",
      "TEE or zk prover",
      "automatic settlement layer"
    ]
  },
  "stage": {
    "round": "pre-seed",
    "revenue": "pre-revenue",
    "customers": 0,
    "design_partners": 0,
    "hosted_ga": false,
    "soc2": false,
    "external_pen_test": false,
    "live_oidc_provider_validation": false,
    "production_cloud_benchmark": false
  },
  "verified_facts": {
    "working_system": [
      "Rust broker: authorize -> policy -> credential/grant -> receipt -> chain -> verify",
      "TypeScript control plane with OIDC sessions, orgs, environments, agent keys, authority tokens, actions, evidence, analytics, audit",
      "Tenant portal and public verifier",
      "Provider adapters: Stripe, AWS STS, GitHub; preview Slack/Zendesk/OpenAI/Anthropic/LangChain",
      "SDKs: TypeScript, Python, LangChain, MCP adapter",
      "EIP-712 signed v2 receipts, canonical hashing, per-agent hash chains, optional Merkle anchoring",
      "KMS/HSM signing bridge; fail-closed signing",
      "Offline verifier and browser tamper demo",
      "300+ tests"
    ],
    "published_packages": {
      "npm": {
        "packages": [
          "@tessera-verify/receipt-schema",
          "@tessera-verify/verify",
          "@tessera-verify/sdk-ts",
          "@tessera-verify/langchain",
          "@tessera-verify/mcp-adapter"
        ],
        "version": "0.1.3",
        "note": "0.1.2 is deprecated because it was published with unresolved workspace dependencies."
      },
      "pypi": {
        "package": "tessera-verify",
        "version": "0.1.2",
        "import": "tessera_verify"
      }
    },
    "benchmarks": {
      "environment": "Apple M5, 16 GB RAM, macOS, Rust 1.98.1, Node 22, mock issuer, local Postgres",
      "policy_eval_us": 4.70,
      "canonical_hash_us": 1.30,
      "receipt_payload_hash_us": 5.37,
      "eip712_sign_us": 23.42,
      "http_in_memory": {"throughput_rps": 955, "p50_ms": 3.87, "p95_ms": 6.10, "p99_ms": 10.25},
      "http_postgres": {"throughput_rps": 410, "p50_ms": 8.12, "p95_ms": 22.34, "p99_ms": 28.03},
      "same_agent_concurrency_postgres": {"requests": 240, "concurrency": 24, "throughput_rps": 500.9, "p50_ms": 44.98, "p95_ms": 50.46, "p99_ms": 66.66, "errors": 0, "chain_verified": true},
      "offline_verify": {"receipt_bytes": 2243, "iterations": 10000, "mean_ms": 1.000, "p50_ms": 0.977, "p95_ms": 1.130, "p99_ms": 1.204},
      "not_measured": ["production cloud/KMS latency", "cost per 1000 actions in cents", "live provider latency", "live OIDC round trip", "multi-region"]
    },
    "guarantee_levels": [
      {"level": "Level 1", "label": "broker-proxied", "proves": "broker forwarded the exact call and signed the observed response", "does_not_prove": "provider execution correctness or lawful intent"},
      {"level": "Level 1", "label": "broker-held grant", "proves": "broker authorized the grant; provider key never exposed", "does_not_prove": "future misuse of other credentials"},
      {"level": "Level 2", "label": "scoped credential", "proves": "broker authorized a provider-scoped credential and recorded the reported outcome", "does_not_prove": "provider used it exactly as authorized; outcome is caller-reported"},
      {"level": "Caller-asserted", "label": "caller-asserted authority", "proves": "what the broker recorded under the caller-supplied principal", "does_not_prove": "IdP authentication"}
    ],
    "pricing": {
      "developer": {"price": "$0", "actions": 1000, "environments": 1},
      "team": {"price_usd_month": 1500, "actions": 250000, "environments": 3},
      "growth": {"price_usd_month": 3500, "actions": 1000000, "environments": 10},
      "enterprise": {"price_usd_year_min": 40000, "actions": 5000000, "self_hosted": true},
      "overage_usd_per_action": 0.004,
      "model": "SaaS + usage; no token; no per-seat pricing"
    },
    "market_estimates": [
      {"source_id": "S1", "metric": "AI governance spending", "value": "$492M in 2026; >$1B by 2030", "caveat": "Gartner; broad governance definition"},
      {"source_id": "S2", "metric": "AI agent governance", "value": "$290M in 2025; $2.3B by 2028", "caveat": "Agent OS vendor research; directional"},
      {"source_id": "S3", "metric": "Agent management/gateways/identity/eval", "value": "$1.0-1.5B in 2026; $15-22B by 2033", "caveat": "Meticulous; broad category"},
      {"source_id": "S4", "metric": "Private companies in agent security/risk", "value": 163, "caveat": "CB Insights company count, not revenue"}
    ],
    "competition": [
      {"category": "agent identity/access", "examples": ["Okta", "Microsoft Entra Agent ID", "Hush", "Oasis", "Astrix"], "gap": "portable per-action evidence with credential/outcome binding"},
      {"category": "observability/gateways", "examples": ["LangSmith", "Arize", "Portkey", "Cloudflare AI Gateway"], "gap": "signed enforcement evidence"},
      {"category": "governance/GRC", "examples": ["Credo AI", "Geordie", "ModelOp", "Holistic AI"], "gap": "per-action enforcement and verifiable receipts"},
      {"category": "verifiable execution/receipts", "examples": ["Dapr 1.18", "PipeLab", "Aqta", "Zanii", "Action State"], "gap": "enterprise enforcement + provider adapters + reviewer workflow"},
      {"category": "TEE/zk", "examples": ["Primus zkTLS", "zkAgent", "Proof-of-Guardrail"], "gap": "latency/cost/integration for first Web2 wedge"},
      {"category": "agent payments", "examples": ["AP2", "x402"], "gap": "execution evidence behind the payment; complementary"}
    ],
    "differentiation": [
      "Broker-mediated per-action enforcement",
      "Provider-specific credential handling and broker-held grants",
      "Signed receipt binds human, agent, intent, policy, tool, credential, and outcome",
      "Open-source offline verifier",
      "Evidence packs and reviewer links",
      "Explicit Level 1/2/caller-asserted guarantee labels"
    ]
  },
  "slides": [
    {
      "n": 1,
      "title": "Title & Hook",
      "key_message": "Tessera enforces what an agent may do and proves what it did.",
      "bullets": ["The enforcement and evidence layer for AI agent actions", "Pre-seed, pre-revenue", "Contact: founders@thetessera.xyz"],
      "source_refs": ["S16"]
    },
    {
      "n": 2,
      "title": "The Shift",
      "key_message": "Agents are moving from text generation to consequential execution.",
      "bullets": ["Write/spend actions: refunds, provisioning, code, support, procurement", "Security teams ask for attribution, exact call, credential, and outcome", "MCP/AP2/x402 normalize access and payments; execution evidence is missing"],
      "source_refs": ["S5", "S6", "S10", "S11", "S25"]
    },
    {
      "n": 3,
      "title": "The Problem",
      "key_message": "Logs are not evidence; identity, traces, and GRC do not bind the exact action.",
      "bullets": ["Which agent acted for which human?", "What exact call and policy version?", "Which scoped credential?", "What happened and can a third party verify it?"],
      "source_refs": ["S16"]
    },
    {
      "n": 4,
      "title": "The Solution",
      "key_message": "Enforce, bind, verify, prove.",
      "bullets": ["Enforce per-action policy", "Issue scoped credential or broker-held grant", "Sign the action record", "Verify offline and share evidence"],
      "source_refs": ["S16"]
    },
    {
      "n": 5,
      "title": "Architecture",
      "key_message": "Broker-mediated enforcement; no TEE/zk dependency in v1.",
      "bullets": ["Control plane: OIDC, agent keys, authority tokens, tenants", "Rust broker: policy, issuers, signer, chain", "Provider APIs/proxy", "EIP-712 receipt -> hash chain -> verifier/evidence"],
      "source_refs": ["S16"]
    },
    {
      "n": 6,
      "title": "Guarantee Model",
      "key_message": "Label what is proven; never overclaim.",
      "bullets": ["Level 1 broker-proxied: exact call + observed outcome", "Level 1 broker-held grant: provider key never reaches agent", "Level 2 scoped credential: authorization + caller-reported outcome", "Caller-asserted: no verified authority artifact"],
      "source_refs": ["S16"]
    },
    {
      "n": 7,
      "title": "Beachhead",
      "key_message": "One consequential write/spend action at an AI-native B2B vendor.",
      "bullets": ["Fintech/support: Stripe refunds", "Cloud/devtools: AWS/GitHub changes", "Support ops: customer-data and ticket updates", "Later: agent-to-agent commerce and DeFi execution"],
      "source_refs": ["S16"]
    },
    {
      "n": 8,
      "title": "Market & Timing",
      "key_message": "A security budget exists; the category is forming; evidence is the missing layer.",
      "bullets": ["Gartner $492M 2026 -> >$1B 2030", "Agent OS $290M 2025 -> $2.3B 2028", "163 private agent-security companies", "No token or new chain required"],
      "source_refs": ["S1", "S2", "S3", "S4"]
    },
    {
      "n": 9,
      "title": "Competition",
      "key_message": "Receipts are not enough; enforcement + integrations + reviewer workflow are the moat.",
      "bullets": ["Identity vendors: identity/lifecycle, not action evidence", "Observability: traces, not signed evidence", "GRC: control mapping, not enforcement", "Receipt tools: primitives, not enterprise enforcement"],
      "source_refs": ["S5", "S6", "S7", "S8", "S9", "S12", "S13", "S14", "S15"]
    },
    {
      "n": 10,
      "title": "Business Model",
      "key_message": "SaaS + usage; no token; land with design partners.",
      "bullets": ["Team $1,500/mo; Growth $3,500/mo; Enterprise $40k+/yr", "Overage $0.004/action", "Free 6-week design partner pilot", "Expand through environments, volume, evidence, self-host"],
      "source_refs": ["S16"]
    },
    {
      "n": 11,
      "title": "Traction & Roadmap",
      "key_message": "Working code, no pretend customers.",
      "bullets": ["Broker/control plane/portal/verifier/SDKs built", "300+ tests; npm/PyPI packages; local benchmarks", "Pre-revenue; no SOC 2/pen test; hosted deployment pending", "0-3 months: hosted + live OIDC + 3 design partners", "3-6 months: accepted evidence + 2 paid pilots", "6-12 months: SOC 2 readiness + 10 paid accounts"],
      "source_refs": ["S16"]
    },
    {
      "n": 12,
      "title": "Team & Ask",
      "key_message": "Raising a pre-seed to turn working security software into repeatable paid evidence.",
      "bullets": ["Founder background: requires founder input", "Recommended range: $1.0M-$1.5M SAFE (requires confirmation)", "18-month runway", "50% engineering/security, 20% design partners/GTM, 15% compliance/audit, 15% infra/ops", "Milestones: 3 design partners, 1 accepted evidence pack, 2 paid pilots, 10 paid accounts"],
      "source_refs": ["S16"]
    }
  ],
  "objection_handling": [
    {"objection": "We already log everything.", "response": "Logs are self-asserted and mutable. Tessera signs the exact action and lets a third party verify it offline. The receipt labels broker-observed vs caller-reported outcomes."},
    {"objection": "Okta/Microsoft give us agent identity.", "response": "They answer who the agent is and what it can reach. Tessera answers what exact action happened, under which policy and credential, and whether the record was altered."},
    {"objection": "We can build this in-house.", "response": "You can build a receipt library. The hard parts are broker enforcement, provider adapters, credential scoping, tenant isolation, authority binding, evidence workflow, and independent verification. Tessera is already working."},
    {"objection": "Why not TEE/zk?", "response": "They add latency, cost, and integration complexity. The first enterprise wedge needs portable authorization + credential + outcome evidence, not proof of inference. We can add zkTLS/TEE for provider-observed claims later."},
    {"objection": "Why no token?", "response": "Enterprise buyers do not want a token in the critical security path. We use SaaS + usage and an open verifier. Receipts can anchor to any rail if agent-to-agent settlement becomes the wedge."},
    {"objection": "This is a crowded market.", "response": "Identity, observability, GRC, receipts, and payments are all adjacent. None combines broker enforcement, provider-specific credential handling, signed receipts, offline verification, and reviewer evidence in one path."},
    {"objection": "You are pre-revenue.", "response": "Yes. The working system, tests, security docs, packages, and benchmarks are public. The next milestone is a real reviewer accepting an evidence pack, not another prototype."}
  ],
  "forbidden_claims": [
    "SOC 2 certified",
    "external penetration test completed",
    "production customers or revenue",
    "live Okta/Entra/Auth0 validation",
    "production cloud/KMS benchmark",
    "TEE, zkVM, zkTLS, or proof of inference",
    "automatic settlement",
    "token, staking, or slashing",
    "tamper-proof or immutable",
    "all provider actions are broker-observed",
    "evidence pack is a certification"
  ],
  "required_founder_input": [
    "founder name and background",
    "final raise amount",
    "SAFE terms / valuation cap / discount",
    "named design partners or LOIs, if any",
    "preferred investor intro ask"
  ],
  "source_registry": [
    {"id": "S1", "title": "Gartner: Global AI Regulations Fuel Billion-Dollar Market for AI Governance Platforms", "date": "2026-02-17", "url": "https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms"},
    {"id": "S2", "title": "Agent OS: State of AI Agent Governance 2026", "date": "2026", "url": "https://vantageaiadvisory.com/agent-os/report-2026"},
    {"id": "S3", "title": "Meticulous Research: AI Agent Governance Platforms Outlook 2026-2033", "date": "2026-09-27", "url": "https://www.meticulousresearch.com/meticulous-next/ai-agent-governance-the-next-control-layer-for-enterprises"},
    {"id": "S4", "title": "CB Insights: AI agents are getting the keys", "date": "2026-09-24", "url": "https://research.cbinsights.com/ai-agents-are-getting-the-keys"},
    {"id": "S5", "title": "Okta for AI Agents", "date": "2026", "url": "https://www.okta.com/products/govern-ai-agent-identity/"},
    {"id": "S6", "title": "Microsoft Entra Agent ID governance", "date": "2026-11-11", "url": "https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview"},
    {"id": "S7", "title": "LangSmith Observability", "date": "2026", "url": "https://www.langchain.com/langsmith/observability"},
    {"id": "S8", "title": "Arize: LLM gateway comparison", "date": "2026-08-27", "url": "https://arize.com/resources/best-llm-gateways-comparison"},
    {"id": "S9", "title": "CNCF/Dapr: Verifiable Execution", "date": "2026-06-11", "url": "https://www.cncf.io/blog/2026/06/11/introducing-verifiable-execution-in-dapr-1-18/"},
    {"id": "S10", "title": "Agent Payments Protocol (AP2) specification", "date": "2026", "url": "https://ap2-protocol.org/ap2/specification/"},
    {"id": "S11", "title": "Agent payments: AP2 and x402 compared", "date": "2026-09-26", "url": "https://emissar.ai/learn/agent-payments"},
    {"id": "S12", "title": "PipeLab: Agent Action Receipts", "date": "2026-05-21", "url": "https://pipelab.org/learn/agent-action-receipts"},
    {"id": "S13", "title": "Aqta: Receipts for the Age of Agents", "date": "2026", "url": "https://aqta.ai/manifesto"},
    {"id": "S14", "title": "DCS Labs: Can they prove what they did?", "date": "2026-10-18", "url": "https://dcslabs.ai/news/can-they-prove-what-they-did"},
    {"id": "S15", "title": "Primus: Verifiable AI Agent Execution", "date": "2026", "url": "https://docs.primuslabs.xyz/implementation-scenarios/provable-agent-execution/"},
    {"id": "S16", "title": "Tessera repository and docs", "date": "2026-11-12", "url": "local repository"},
    {"id": "S22", "title": "Hush Security $30M Series A", "date": "2026-07-28", "url": "https://www.hush.security/resources/hush-security-raises-30m-to-close-the-ai-agent-governance-gap-with-akamai-joining-as-strategic-investor"},
    {"id": "S23", "title": "Geordie AI $30M Series A", "date": "2026-05-28", "url": "https://www.geordie.ai/resources/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/"},
    {"id": "S24", "title": "Eve Security seed extension", "date": "2026-09-15", "url": "https://www.prnewswire.com/news-releases/eve-security-extends-seed-round-to-7-5-million-as-rogue-ai-agents-turn-runtime-security-into-an-enterprise-imperative-302878598.html"},
    {"id": "S25", "title": "Okta Agent SSO / 34% survey", "date": "2026-08-24", "url": "https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso"},
    {"id": "S17", "title": "Zanii: Proof-of-Action for AI Agents", "date": "2026", "url": "https://proof.zanii.agency/zanii-proof-of-action.pdf"},
    {"id": "S18", "title": "Action State: receipts for AI-agent actions", "date": "2026-10-22", "url": "https://dataphoenix.info/news/action-state-agent-evidence-tools"},
    {"id": "S19", "title": "agent-attestation receipts library", "date": "2026", "url": "https://github.com/p-vbordei/agent-attestation"},
    {"id": "S20", "title": "zkAgent: Verifiable Agent Execution", "date": "2026", "url": "https://iacr.org/news/item/27639"},
    {"id": "S21", "title": "Proof-of-Guardrail in AI Agents", "date": "2026", "url": "https://arxiv.org/abs/2603.05786"}
  ]
}
```

## Agent Q&A map

| Question | Answer source | Required caution |
|---|---|---|
| What does Tessera do? | `product.one_liner` | Do not call it a dashboard or identity product |
| Who buys it? | `product.buyer` | It is a design-partner wedge, not mass adoption |
| Is it live? | `stage.hosted_ga` | No |
| Do you have customers? | `stage.customers` | No; pre-revenue |
| What is the moat? | `differentiation` | Enforcement + integrations + evidence workflow, not receipts alone |
| Does it use TEE/zk? | `product.not` + lightpaper trade-offs | No; explain why |
| Is there a token? | `pricing.model` | No |
| What is the raise? | `required_founder_input` | Recommended range only; founder must confirm |
| What is the market size? | `market_estimates` | Use ranges, cite source, state definition |
| What can go wrong? | lightpaper `threat_model` | Be explicit about Level 2 and caller-reported outcomes |

## Handoff checklist

Before using this deck externally:

- [ ] Founder fills team slide.
- [ ] Founder confirms raise amount and SAFE terms.
- [ ] Remove or label any placeholder design partner names.
- [ ] Re-check market estimates and dates.
- [ ] Keep the “pre-revenue” and “no SOC 2/pen test” statements unless they become false.
- [ ] Do not add customer logos without written permission.
