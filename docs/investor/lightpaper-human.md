# Tessera Lightpaper

**Proof of action for AI agents**  
**Version:** 0.1 · 2026-11-12  
**Audience:** investors, design partners, enterprise security reviewers  
**Status:** pre-seed, pre-revenue, working prototype  
**Contact:** founders@thetessera.xyz  
**Companion deck:** [`pitch-deck-human.md`](pitch-deck-human.md)

> This is a Notion-friendly technical memo. It is deliberately narrower than a marketing deck: it states what the current system enforces, observes, and proves — and what it does not.

---

## Executive summary

AI agents are moving from generating text to executing consequential actions: moving money, changing infrastructure, updating customer records, and invoking tools through MCP and provider APIs. Enterprises can identify an agent and observe its traces, but they cannot easily prove **what the agent actually did, on whose authority, with which scoped credential, and what the outcome was** in a form a third party can verify independently.

Tessera is the enforcement and evidence layer for those actions. It sits between the agent and the provider:

1. **Enforce** the declared intent against per-action policy.
2. **Issue** a scoped credential, or a broker-held grant the agent never sees.
3. **Bind** the agent, delegating human, intent, policy hash, tool definition, arguments, credential, and outcome into an EIP-712-signed action record.
4. **Chain** records per agent and optionally anchor Merkle roots.
5. **Verify** offline with an open-source verifier.
6. **Prove** with a verification page and reviewer evidence pack.

The product is pre-revenue and the hosted deployment is not yet live. The working system already includes the Rust broker, TypeScript control plane, tenant portal, public verifier, provider adapters, SDKs, 300+ tests, security documentation, and reproducible benchmarks. The next milestone is not “invent the protocol”; it is “get a real security reviewer to accept one evidence pack.”

---

## 1. Why now

Three shifts are happening at once.

### 1.1 Agents are becoming principals with authority

Enterprises are giving agents access to systems that write and spend. The buyer’s security team is no longer asking only “which model is this?” It is asking:

- Which agent acted, and for which human?
- What exact tool call was authorized?
- Which credential did it receive, and how long was it valid?
- What happened, and can an outside party verify the record?

Traditional IAM establishes identity and access. It does not bind the exact call, the policy version, the credential, and the outcome into portable evidence.

### 1.2 The market is converging on agent security

The category is forming quickly:

- Okta has shipped agent identity, lifecycle governance, and runtime gateway controls. Microsoft Entra Agent ID provides identity, sponsorship, conditional access, and lifecycle governance for agents. [S5][S6]
- Hush Security raised a $30M Series A for non-human identity and agent governance [S22]; Geordie AI raised a $30M Series A for agent security and governance [S23]; Eve Security extended its seed to $7.5M for runtime agent security [S24]; Outerlimit is another entrant in this category [S4].
- CB Insights tracked **163 private companies** across AI agent security and risk management in September 2026. [S4]
- Gartner estimates AI governance spending at **$492M in 2026**, surpassing **$1B by 2030**. [S1]
- Agent OS estimates agent governance at **$290M in 2025 → $2.3B by 2028**, while Meticulous Research gives a broader **$1.0–1.5B in 2026 → $15–22B by 2033** range for agent management, gateways, identity, and evaluation tooling. [S2][S3]

The numbers vary because the category is being defined. The directional signal is consistent: security budgets are moving toward agent control, identity, and evidence.

### 1.3 Standards are converging, but the evidence layer is missing

MCP normalizes tool access. OAuth 2.1 and OIDC normalize delegated identity. AP2 and x402 normalize payment authorization and settlement. [S10][S11]

None of these standards alone produces a portable, verifiable record of the action that happened between the authorization and the outcome. AP2 proves “the user authorized this.” x402 moves the payment. Tessera is designed to prove “this agent took this action, under this policy, with this credential, and here is the recorded outcome” — with explicit labels for what was observed and what was reported.

---

## 2. The problem

### 2.1 Logs are self-asserted

An agent runtime can write a log line for an action that never happened, omit an action that did happen, or rewrite history after the fact. A reviewer cannot distinguish a truthful log from a convincing one.

### 2.2 Identity is not proof

IAM answers “who is the agent?” and “what can it reach?” It does not bind the exact tool call, the delegating human, the policy version, the arguments, the credential, and the outcome into one artifact.

### 2.3 Observability is not attestation

Agent observability platforms are excellent for debugging and evaluation. Traces are not designed as signed, portable evidence, and they generally depend on the operator’s telemetry pipeline. [S7][S8]

### 2.4 GRC is not enforcement

Governance platforms can inventory systems, map controls, and collect evidence. They do not sit on the execution path and enforce the exact action before it happens.

### 2.5 The buyer is specific

The beachhead is an AI-native B2B vendor, roughly 20–200 people, selling an agentic product to enterprises, where the agent takes **write or spend** actions in the customer’s systems. The trigger is a specific enterprise deal stuck in security review. The buyer is the CTO, Head of Security, or Head of Platform; the economic buyer may be the CEO/COO.

The first product is not a universal agent economy protocol. It is a six-week design-partner pilot that instruments one consequential action and produces evidence a reviewer will accept.

---

## 3. The product

Tessera is an enforcement and evidence layer. It is delivered as:

- **Rust broker** — authorize, policy evaluation, credential issuance/proxy, receipt signing, chain, revocation, quotas, anchoring.
- **Control plane** — OIDC sessions, orgs, environments, agent keys, authority tokens, action read model, evidence, analytics.
- **Tenant portal** — actions, agents, policies, integrations, reviews, evidence packs, settings.
- **Public verifier** — offline receipt/chain verification and tamper demo.
- **SDKs** — TypeScript, Python, LangChain, MCP adapter.

### 3.1 The execution path

```text
Agent / SDK / MCP
   │  agent API key + exact tool call + intent + args
   ▼
Control plane
   │  OIDC, tenant, environment, authority token
   ▼
Rust broker
   │  policy → scoped credential or broker-held grant
   ├──────────────► Provider API / proxy
   │                         │
   ▼                         ▼
EIP-712 action record ◄── outcome / observed response
   │
   ▼
Hash-linked chain → optional Merkle anchor
   │
   ▼
Offline verifier / evidence pack / reviewer link
```

### 3.2 What the receipt contains

A v2 receipt binds:

- tenant, agent, and acting human/principal
- intent hash and declared purpose/risk class
- policy id, version, hash, decision, and reason code
- tool identity, tool-definition hash, and argument hash
- credential issuer, type, scopes, TTL, single-use flag, and non-secret thumbprint
- outcome status, source (`broker_observed` or `agent_reported`), and result hash
- EIP-712 signature, signer key id, timestamp, optional anchor reference, and `prev` chain hash

The receipt contains hashes, not raw sensitive arguments. The evidence pack adds policy versions, authority transitions, key events, anchors, and a reviewer report.

### 3.3 What the verifier checks

- EIP-712 signature over the canonical payload
- expected signer, if supplied or pinned
- payload hash
- chain link (`prev`)
- optional Merkle proof / anchor reference
- the recorded guarantee level

Verification runs in the browser or CLI and makes no call to Tessera.

---

## 4. Guarantee model: what is actually proven

“Proof of action” can mean many things. Tessera labels the guarantee instead of flattening every path into one claim.

| Level | Path | What is proven | What is not proven |
|---|---|---|---|
| **Level 1 — broker-proxied** | Broker holds the provider credential; proxy re-checks `argsHash` and grant expiry | The broker forwarded this exact call and signed the observed response | That the provider executed correctly; that the business intent was lawful |
| **Level 1 — broker-held grant** | Provider key stays in the broker; agent gets a grant id | The broker authorized the grant; the provider key was never exposed | That a later direct credential cannot be misused elsewhere |
| **Level 2 — scoped credential** | Broker authorizes a provider-scoped token/session | The broker authorized the credential and recorded the reported outcome | That the provider used the credential exactly as authorized; the outcome is caller-reported |
| **Caller-asserted** | No verified authority artifact | What the broker recorded, under the caller-supplied principal | That an IdP authenticated the delegation |

This is a deliberate product choice. Enterprise security buyers do not want a vendor that claims more than its evidence supports. The same labels appear in the receipt, the verifier, and the portal.

---

## 5. Architecture and trust boundaries

### 5.1 Components

- **Control plane (`apps/api`)** — Hono/TypeScript API. Handles OIDC, sessions, RBAC, agent keys, environments, action read model, evidence packs, verification links, integrations, audit.
- **Broker (`apps/broker`)** — Rust service. Handles authorize, policy evaluation, credential issuance/proxy, receipt signing, chain, revocation, quotas, authority transitions, anchors, key events, administrative APIs.
- **Issuer adapters** — Stripe (broker-held grants), AWS STS, GitHub App; preview adapters for Slack, Zendesk, OpenAI, Anthropic, LangChain.
- **Stores** — Postgres for policies, chain, grants, telemetry, revocations, anchors, key events; Redis for caches and rate limits; in-memory fallbacks for tests.
- **Signer** — local secp256k1 signer or KMS/HSM bridge. Signing failures fail closed; no unsigned fallback.
- **Verifier** — independent TypeScript verifier and CLI; public browser verifier.
- **SDKs** — TypeScript, Python, LangChain, MCP.

### 5.2 Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Agent runtime | Sending the declared intent and call; reporting outcome when not broker-observed | Proving its own honesty or omitting receipts |
| Control plane | Auth, tenant scoping, key issuance, authority-token minting | Provider execution; it is not the receipt authority |
| Broker | Policy decision, credential/grant issuance, signing, chain | Provider correctness; model intent |
| Provider | Enforcing its credential scope | Binding arbitrary tool arguments unless the provider supports it |
| Verifier | Independent signature/hash/chain check | Semantic correctness of the action |
| Operator | Running the service, key custody, availability | Being trusted without evidence; self-hosting is available for enterprise |

### 5.3 Human authority

OIDC login establishes the human. The control plane binds an agent key to a human (`owner` mode) or accepts a short-lived per-call authority token (`token` mode). The broker verifies:

- HS256 signature and `kid` keyring
- issuer and audience
- subject, expiry, `jti`
- tenant and agent scope
- replay via a Redis-or-memory `jti` cache

The receipt records `verificationMethod: "hmac-jwt"` and the OIDC-derived authority reference. This closes the “caller-asserted user ID” gap without requiring broker-side OIDC/JWKS in v1.

---

## 6. Threat model

| Threat | Current defense | Residual risk |
|---|---|---|
| Agent claims an action it never took | Broker writes the authorization; outcomes from `/v1/proxy` are broker-observed; `/v1/record` outcomes are explicitly caller-reported | Native credentials and direct tools remain caller-reported |
| Agent omits a receipt | Broker writes on the governed path; chain and anchor make omission visible within that path | An agent that bypasses the broker is outside coverage; egress controls are a future hardening layer |
| Stolen agent key | Per-environment keys, tenant/agent scoping, revocation, quotas, authority-token binding | A stolen key can act within its scope until revoked; detection depends on monitoring |
| Replay of an action or token | Idempotency keys, single-use credentials, `argsHash`, chain link, `jti` replay cache | Long-lived native credentials can be reused outside the broker |
| Receipt tampering | EIP-712 signature, canonical payload hash, per-agent hash chain, optional anchor | A database administrator can rewrite local state if no external anchor/export exists |
| Verifier collusion | Open-source offline verifier; pin expected signer; no server dependency | The verifier trusts the broker’s signing key and the deployment’s domain |
| Cross-tenant access | Tenant-scoped broker stores, per-environment keys, tenant-isolation tests, optional Postgres RLS | Control-plane tables are application-enforced, not fully RLS-covered |
| Provider spoofing / wrong response | Broker-held grants proxy and observe the response | Direct bearer/AWS/GitHub outcomes are caller-reported |
| Prompt injection / malicious tool | Per-action policy, allowlists, tool-definition pinning, risk classes | Does not prove the model’s reasoning or that the human intent was lawful |
| Broker compromise | KMS/HSM bridge, fail-closed signing, key rotation, revocations, audit, self-host option | A fully compromised broker can sign false records; anchoring and independent operation reduce but do not eliminate this |
| Time ambiguity | Signed timestamps, optional RFC 3161 timestamp / on-chain anchor | No universal trusted time for every deployment |

The central honest claim: **Tessera proves what the broker signed and what the evidence path supports. It does not prove the model’s internal reasoning or guarantee provider correctness.**

---

## 7. Architectural trade-offs

### 7.1 Broker-mediated enforcement vs a decentralized protocol

We chose a broker because it can actually enforce the policy, hold or scope the credential, and observe the response. A purely client-side receipt library cannot prevent an agent from bypassing the receipt.

The cost is a trust anchor. We mitigate it with:

- open-source verifier and schemas,
- offline verification with pinned signer,
- optional on-chain anchoring,
- KMS/HSM signing,
- self-hosted enterprise deployment,
- evidence exports that survive the vendor.

This is not a trustless system. It is a system that minimizes the trust required and makes the remaining trust explicit.

### 7.2 EIP-712 receipts vs TEEs and zk proofs

TEEs and zk proofs can strengthen specific claims:

- zkTLS can attest that an HTTPS request/response occurred.
- TEE attestation can prove code ran in an enclave.
- zkVM/zkAgent can prove model execution or agent trajectories.

They also add latency, cost, integration complexity, and new trust assumptions. For the first enterprise wedge, the buyer needs portable evidence of authorization, credential binding, and observed/reported outcome — not a proof of inference. We chose EIP-712 + hash chains + optional anchoring because they are fast, provider-agnostic, and easy to verify offline.

We can add zkTLS or TEE attestations later for provider-observed claims, but they are not required for the v1 product.

### 7.3 Native credentials remain caller-reported

AWS STS, GitHub installation tokens, and OAuth bearer tokens are scoped by the provider, not by the tool arguments. Tessera can authorize issuance and record the reported outcome, but it cannot prove the exact use of a native credential after issuance. The receipt labels this as Level 2.

This is a product boundary, not a temporary bug. The broker-held grant/proxy path exists precisely to move high-value actions into Level 1.

### 7.4 No token

We deliberately do not use a token, staking, or slashing. Enterprise buyers do not want a token in the critical path of a security review. The business is SaaS + usage, with an open-source verifier and an enterprise self-host option.

If agent-to-agent settlement becomes a wedge, Tessera receipts can anchor to any chain or payment rail. We do not need to own the settlement layer.

### 7.5 Optional anchoring

Anchors provide external existence/time evidence, but they add chain cost and operational complexity. The default path is signed records, hash chains, and offline verification; anchoring is optional for customers who need stronger external evidence.

---

## 8. Benchmarks and cost

The current numbers are local, reproducible, and deliberately labeled as non-production.

### 8.1 Microbenchmarks

| Benchmark | Result |
|---|---:|
| Policy evaluation (constraint + CEL) | 4.70 µs |
| Canonical JSON + Keccak hash | 1.30 µs |
| Receipt payload hash | 5.37 µs |
| EIP-712 receipt signing | 23.42 µs |

### 8.2 HTTP authorize latency

**In-memory broker, mock issuer, 200 requests, concurrency 4:**

| Metric | Result |
|---|---:|
| Throughput | 955 req/s |
| p50 / p95 / p99 | 3.87 / 6.10 / 10.25 ms |

**Postgres broker, mock issuer, 200 requests, concurrency 4:**

| Metric | Result |
|---|---:|
| Throughput | 410 req/s |
| p50 / p95 / p99 | 8.12 / 22.34 / 28.03 ms |

### 8.3 Same-agent concurrency

Postgres, 240 requests, concurrency 24:

| Metric | Result |
|---|---:|
| Throughput | 500.9 req/s |
| p50 / p95 / p99 | 44.98 / 50.46 / 66.66 ms |
| Errors | 0 |
| Chain length / verified | 240 / true |

### 8.4 Offline verification

| Metric | Result |
|---|---:|
| Receipt size | 2,243 bytes |
| Iterations | 10,000 |
| Mean | 1.000 ms |
| p50 / p95 / p99 | 0.977 / 1.130 / 1.204 ms |

### 8.5 What is not measured

- Production cloud latency and cost (EC2/RDS/KMS)
- Live provider latency and error rates
- Cost per 1,000 actions in cents
- Multi-region behavior
- A live OIDC provider round trip

We should not invent those numbers. A cloud/KMS benchmark runbook is committed; the next capital milestone includes running it.

**Environment:** Apple M5, 16 GB RAM, macOS, Rust 1.98.1, Node 22, mock issuer, local Postgres. These are regression/diligence numbers, not an SLA.

---

## 9. Competitive landscape

Tessera sits at the intersection of several categories. The closest alternatives solve adjacent problems, not the full enforcement + evidence path.

| Category | Examples | Strength | Gap relative to Tessera |
|---|---|---|---|
| Agent identity / access | Okta, Microsoft Entra Agent ID, Hush, Oasis, Astrix | Inventory, lifecycle, access policy, runtime control | Portable per-action evidence with credential/outcome binding |
| Agent observability / gateways | LangSmith, Arize, Portkey, Cloudflare AI Gateway | Traces, evals, cost, routing, guardrails | Signed, independently verifiable enforcement evidence |
| AI governance / GRC | Credo AI, Geordie, ModelOp, Holistic AI | Policy workflow, inventories, control mapping | Per-action enforcement and verifiable receipts |
| Verifiable execution / receipts | Dapr 1.18, PipeLab, Aqta, Zanii, Action State, agent-attestation | Signed records, hash chains, transparency | Enterprise enforcement, provider adapters, reviewer workflow |
| TEE / zk | Primus zkTLS, zkAgent, Proof-of-Guardrail | Strong request/inference attestation | Latency, cost, integration; not our first wedge |
| Agent payments | AP2, x402 | Authorization and settlement | Execution evidence for the action behind the payment |

### The positioning

**Identity vendors answer “who is the agent.” Observability answers “what did the system trace.” Tessera answers “what did the agent do, on whose authority, with what credential, and can a third party verify it.”**

Receipt primitives are becoming commodity. The defensible product is the combination of:

1. broker-mediated enforcement,
2. provider-specific credential handling,
3. signed receipts and chains,
4. offline verification,
5. evidence packs and reviewer workflow,
6. tenant/authority controls.

---

## 10. Market and business model

### 10.1 Market framing

Use ranges, not a single TAM:

- **Narrow governance/security:** Gartner **$492M in 2026 → >$1B by 2030**; Agent OS **$290M in 2025 → $2.3B by 2028**. [S1][S2]
- **Broader agent management/gateway/identity/eval:** Meticulous **$1.0–1.5B in 2026 → $15–22B by 2033**. [S3]
- **Category heat:** 163 private companies in AI agent security/risk [S4]; Hush $30M Series A [S22], Geordie $30M Series A [S23], Eve $7.5M seed [S24].

The SAM is AI-native B2B vendors with at least one write/spend agent and an enterprise security review, plus regulated mid-market firms with an action-level audit requirement. A bottom-up SAM/SOM model should be completed during diligence; the first commercial proof is 3 design partners and 10 paid accounts.

### 10.2 Pricing

| Tier | Price | Included | Target |
|---|---:|---|---|
| Developer | $0 | 1,000 actions/month, 1 environment | Open-source adoption |
| Team | **$1,500/month** (annual) | 250,000 actions/month, 3 environments, SSO, evidence packs | First enterprise deals |
| Growth | **$3,500/month** (annual) | 1,000,000 actions/month, 10 environments, custom policies | Multiple enterprise customers |
| Enterprise | **$40k+/year** | 5M+ actions, VPC/self-hosted, HSM, DPA, pen-test report | Regulated enterprise / platform |
| Overage | $0.004/action | Beyond included volume | Aligns with usage |

### 10.3 Go-to-market

- Land with a **free 6-week design partner pilot**.
- Instrument one action; produce a verification page and evidence pack.
- Run a tabletop security review with the partner’s security lead.
- Convert to a **$1,500/month** paid pilot if the evidence answers the reviewer.
- Expand through environments, volume, evidence packs, and enterprise/self-host.

The first channel is founder-led outbound to AI-native B2B vendors with a stalled enterprise deal. The second channel is agent platforms and gateways that want to embed verification.

---

## 11. Roadmap

| Phase | Focus | Milestones |
|---|---|---|
| **Now** | Working prototype | Broker, control plane, portal, verifier, SDKs, 300+ tests, local benchmarks |
| **0–3 months** | Hosted proof | Deploy `thetessera.xyz` and `app.thetessera.xyz`; live OIDC; 3 design partners; first evidence pack |
| **3–6 months** | Commercial proof | Reviewer accepts evidence; 2 paid pilots; cloud/KMS benchmark; webhook/SSO polish |
| **6–12 months** | Repeatability | SOC 2 readiness + external pen test; 10 paid accounts; more provider adapters; case study |

### What the raise unlocks

- Engineering and security hardening
- Hosted deployment and live IdP validation
- Design-partner integration and evidence reviews
- Cloud/KMS benchmark
- SOC 2 readiness and penetration test
- First GTM hire

---

## 12. Risks and open questions

### Risks

1. **Category crowding.** Identity vendors and well-funded agent-security startups may bundle adjacent controls. Our answer is the execution-evidence layer and provider-specific enforcement, not a generic dashboard.
2. **Receipt commoditization.** Signed action receipts are becoming easier to build. Our moat must be the enforcement path, integrations, and reviewer workflow.
3. **Trust-anchor criticism.** A broker is a trusted component. We mitigate with open verification, optional anchoring, KMS/HSM, and self-hosting, but we should not call the system trustless.
4. **Native credential limits.** Level 2 outcomes are caller-reported. We must make the boundary clear and move high-value actions to broker-held grants/proxy.
5. **Enterprise sales cycle.** Design partners must have a live stalled deal; this is a sales-qualified wedge, not a bottom-up developer tool.
6. **Pre-revenue execution.** No customers, no SOC 2, no pen test yet. The plan must be milestone-driven.
7. **Founder capacity.** The current product is founder-led; the raise must fund security review and design-partner delivery capacity.

### Open questions for diligence

- Which exact IdP and enterprise buyer will be first?
- What is the first design partner’s action and acceptance criterion?
- What is the cost per 1,000 actions on target cloud infrastructure?
- Which provider adapter produces the clearest Level 1 evidence?
- What is the right price for evidence packs vs action volume?
- Do we need zkTLS/TEE for the first enterprise reviewer, or is broker-observed evidence enough?

---

## 13. Team and ask

### Team

**Founder:** [Name] — [2–3 lines: cryptography, distributed systems, AI, security, or startup background]  
**Why us:** [relevant proof point]  
**Next hires/contracts:** security reviewer, design-partner engineer, GTM lead

### Ask

**Raising:** $1.0M–$1.5M pre-seed on a SAFE *(draft; founder to confirm amount and terms)*  
**Runway:** 18 months

**Use of funds**

| Area | Allocation |
|---|---:|
| Engineering and security | 50% |
| Design partners and GTM | 20% |
| Compliance, audit, pen test | 15% |
| Infrastructure and operations | 15% |

**Milestones**

- Hosted GA + live OIDC
- 3 design partners, 1 accepted evidence pack
- 2 paid pilots
- SOC 2 readiness + external pen test
- 10 paid accounts

---

## Appendix A — Glossary

- **Action record / receipt** — signed v2 record binding authorization, principal, agent, tool, credential, and outcome.
- **Broker-held grant** — provider credential stays in the broker; agent receives a grant id and the broker proxies the call.
- **Scoped credential** — short-lived provider credential issued for one action/resource.
- **Level 1** — broker-proxied or broker-held grant; argument-bound and/or broker-observed.
- **Level 2** — scoped credential; outcome caller-reported.
- **Caller-asserted** — principal supplied by the caller, not verified by an authority token.
- **Evidence pack** — signed archive + reviewer report mapped to controls; evidence mapping, not certification.
- **Tamper-evident** — changes are detectable; not “immutable” or “tamper-proof.”

## Appendix B — What Tessera is not

- Not an identity provider.
- Not an LLM firewall or prompt-injection filter.
- Not an observability/evaluation platform.
- Not a GRC platform or certification.
- Not a token, staking, or slashing protocol.
- Not a TEE/zk prover.
- Not a guarantee that the provider executed correctly.

## Appendix C — Source registry

- **S1** Gartner, AI governance spending, 2026-02-17. https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms
- **S2** Agent OS, State of AI Agent Governance 2026. https://vantageaiadvisory.com/agent-os/report-2026
- **S3** Meticulous Research, AI Agent Governance Platforms Outlook 2026–2033, 2026-09-27. https://www.meticulousresearch.com/meticulous-next/ai-agent-governance-the-next-control-layer-for-enterprises
- **S4** CB Insights, “AI agents are getting the keys,” 2026-09-24. https://research.cbinsights.com/ai-agents-are-getting-the-keys
- **S5** Okta for AI Agents. https://www.okta.com/products/govern-ai-agent-identity/
- **S6** Microsoft Entra Agent ID governance, 2026-11-11. https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview
- **S7** LangSmith Observability. https://www.langchain.com/langsmith/observability
- **S8** Arize, LLM gateways comparison, 2026-08-27. https://arize.com/resources/best-llm-gateways-comparison
- **S9** CNCF/Dapr verifiable execution, 2026-06-11. https://www.cncf.io/blog/2026/06/11/introducing-verifiable-execution-in-dapr-1-18/
- **S10** AP2 specification. https://ap2-protocol.org/ap2/specification/
- **S11** x402 / agent payments comparison, 2026. https://emissar.ai/learn/agent-payments
- **S12** PipeLab, Agent Action Receipts, 2026-05-21. https://pipelab.org/learn/agent-action-receipts
- **S13** Aqta, “Receipts for the Age of Agents,” 2026. https://aqta.ai/manifesto
- **S14** DCS Labs, “Can they prove what they did?,” 2026-10-18. https://dcslabs.ai/news/can-they-prove-what-they-did
- **S15** Primus, Verifiable AI Agent Execution. https://docs.primuslabs.xyz/implementation-scenarios/provable-agent-execution/
- **S16** Tessera repo: `README.md`, `BENCHMARKS.md`, `docs/architecture.md`, `docs/security-guarantees.md`, `docs/receipt-spec.md`, `docs/pricing.md`.
- **S22** Hush Security $30M Series A, 2026-07-28. https://www.hush.security/resources/hush-security-raises-30m-to-close-the-ai-agent-governance-gap-with-akamai-joining-as-strategic-investor
- **S23** Geordie AI $30M Series A, 2026-05-28. https://www.geordie.ai/resources/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/
- **S24** Eve Security seed extension, 2026-09-15. https://www.prnewswire.com/news-releases/eve-security-extends-seed-round-to-7-5-million-as-rogue-ai-agents-turn-runtime-security-into-an-enterprise-imperative-302878598.html
- **S25** Okta Agent SSO / 34% survey, 2026-08-24. https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso
- **S17** Zanii, Proof-of-Action for AI Agents, 2026. https://proof.zanii.agency/zanii-proof-of-action.pdf
- **S18** Action State / Data Phoenix, receipts for AI-agent actions, 2026-10-22. https://dataphoenix.info/news/action-state-agent-evidence-tools
- **S19** agent-attestation receipts library. https://github.com/p-vbordei/agent-attestation
- **S20** zkAgent, IACR 2026. https://iacr.org/news/item/27639
- **S21** Proof-of-Guardrail, arXiv 2603.05786, 2026. https://arxiv.org/abs/2603.05786

---

*Prepared 2026-11-12 from the Tessera repository and public sources. Market estimates are third-party/vendor estimates and should be re-checked before external use. Complete founder and ask placeholders before sending.*
