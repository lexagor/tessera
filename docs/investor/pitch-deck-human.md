# Tessera — Investor Pitch Deck

**Audience:** human investors, design partners, enterprise security reviewers  
**Version:** 0.1 · 2026-11-12  
**Stage:** pre-seed, pre-revenue  
**Contact:** founders@thetessera.xyz  
**Companion memo:** [`lightpaper-human.md`](lightpaper-human.md)

> **Fill before sending:** founder background, final raise amount, SAFE terms, and any named design partners. Everything else below is grounded in the current repository and public sources listed in the appendix.

---

## Slide 1 — Title & Hook

### On the slide

# Tessera

### Enforce what an agent may do. Prove what it did.

The enforcement and evidence layer for AI agent actions.

**Contact:** founders@thetessera.xyz  
**Website:** thetessera.xyz  
**GitHub:** github.com/lexagor/tessera

### Speaker notes

Tessera is not another identity provider, LLM gateway, or observability dashboard. It sits on the execution path: it enforces per-action policy, issues a scoped credential or broker-held grant, and signs a receipt that binds the agent, human authority, exact call, credential, and outcome.

The buyer is an AI-native B2B vendor whose enterprise deal is stuck in security review. The reviewer needs evidence, not another log browser.

---

## Slide 2 — The Shift: Agents Are Moving From Chat to Consequence

### On the slide

**Agents are moving from generating text to taking action.**

- Refunds, payments, and account changes
- Cloud provisioning and code changes
- Customer-data updates and support actions
- Procurement, booking, and workflow execution

**The bottleneck is no longer model quality. It is trust in the action.**

Security teams now ask:

- Which agent acted, and for which human?
- What exact call was authorized?
- Which credential did it receive?
- What happened, and can a third party verify it?

### Speaker notes

The market is converging on this problem from several directions: identity vendors are adding agent identities, gateways are adding runtime controls, and observability platforms are adding agent traces. All of them validate the urgency. None of them produces portable, per-action evidence that a reviewer can verify offline.

Two standards are also converging: MCP for tool access and AP2/x402 for payment authorization. Both need an execution-evidence layer underneath. That is the opening.

### Evidence to cite

- Okta’s 2026 AI Agents at Work report: only **34%** of organizations apply the same security controls to AI agents as to human workers [S25].
- CB Insights (Sep 2026): **163 private companies** across AI agent security and risk management; Hush, Geordie, and Eve are attracting capital [S4][S22][S23][S24].
- Gartner (Feb 2026): AI governance spending is projected at **$492M in 2026**, surpassing **$1B by 2030**.
- AP2 and x402 are standardizing agent payment authorization and settlement; neither proves the provider-side execution by itself.

---

## Slide 3 — The Problem: Logs Are Not Evidence

### On the slide

**The security reviewer cannot answer four questions from today’s stack.**

| Question | What exists today | Why it fails |
|---|---|---|
| Who acted for which human? | IAM, OIDC, agent identity | Proves login/identity, not the exact delegated action |
| What was authorized? | Logs, traces, policy dashboards | Self-asserted; may omit or mutate the record |
| What credential was used? | Secret managers, gateways | Shows access, not the scoped credential bound to the call |
| What actually happened? | Observability, GRC evidence | Traces are not signed; control mappings are not per-action proof |

**Logs are mutable. Identity is not proof. Observability is not attestation. GRC is not enforcement.**

### Speaker notes

The enterprise buyer is not asking for “more AI governance.” They are trying to close a specific deal. Their customer’s security team wants an audit trail, attribution, and proof that the record was not altered.

The wedge is a single consequential action: a refund, a production change, a customer-data update. If we can make that action governable and provable, the deal moves.

---

## Slide 4 — The Solution: Enforce. Bind. Verify. Prove.

### On the slide

**One execution path from policy decision to portable evidence.**

1. **Enforce** — Evaluate per-action policy; issue a scoped credential or a broker-held grant the agent never sees.
2. **Bind** — Sign the agent, human authority, intent, policy hash, tool definition, args hash, credential thumbprint, and outcome.
3. **Verify** — Check the EIP-712 signature, payload hash, and chain offline with the open-source verifier.
4. **Prove** — Share a verification page or an evidence pack mapped to the controls a reviewer asks for.

**The receipt is the product surface. Enforcement is the moat.**

### Speaker notes

The receipt alone is becoming a commodity: several open-source and startup projects now sign action records. The harder product is the path that produces the record: policy enforcement, credential scoping, provider adapters, tenant isolation, authority binding, and reviewer workflow.

Tessera makes the receipt *mean something* because the broker was actually in the execution path.

---

## Slide 5 — How It Works: Broker-Mediated, Not Trust-Me-Bro

### On the slide

```text
Agent SDK / MCP / LangChain
        │  agent API key + exact tool call
        ▼
Control plane
  OIDC · agent keys · authority tokens · tenants
        │  environment-scoped broker key
        ▼
Rust broker
  policy → credential / broker-held grant → signer
        │                         │
        ▼                         ▼
Provider API / proxy       EIP-712 action record
                                  │
                                  ▼
                          Hash-linked chain
                                  │
                                  ▼
                    Offline verifier / evidence pack
```

**Design choices**

- Broker-mediated enforcement with short-lived, scoped credentials
- Broker-held grants for Stripe; the provider key never reaches the agent
- EIP-712 signatures, canonical hashing, per-agent hash chains
- Optional Merkle anchoring; KMS/HSM signing bridge
- OIDC session → short-lived authority token → broker-verified `hmac-jwt`
- Open-source verifier; no call back to Tessera

### Speaker notes

We deliberately do **not** depend on TEEs or zk proofs for v1. That keeps latency and integration cost low and lets us cover Web2 APIs that do not expose attestations. The trade-off is explicit: we prove what the broker authorized, issued, and observed; we do not prove how the model thought.

For broker-held grants, the broker forwards the call and observes the response. For native AWS/GitHub/OAuth credentials, the provider owns the scope and the outcome is caller-reported. We label that difference in the receipt.

---

## Slide 6 — The Guarantee Model: We Label What We Can Prove

### On the slide

| Level | Path | What the receipt proves |
|---|---|---|
| **Level 1 — broker-proxied** | Broker holds the provider credential; proxy re-checks `argsHash` at execution time | The broker forwarded this exact call and signed the observed response |
| **Level 1 — broker-held grant** | Provider key stays in the broker; agent gets a grant id | The broker authorized the grant and the provider key was never exposed |
| **Level 2 — scoped credential** | Broker authorizes a provider-scoped token/session | The broker authorized the credential; the outcome is caller-reported |
| **Caller-asserted** | No verified authority artifact | The record shows what the broker recorded, not that an IdP authenticated the delegation |

**Tamper-evident, not tamper-proof. Evidence mapping, not certification.**

### Speaker notes

Enterprise security buyers punish overclaiming. Our differentiation is not just cryptography; it is honesty about the guarantee boundary. The verifier shows the same Level 1/Level 2/caller-asserted label the receipt carries.

This is also why “proof of action” is the right category: the reviewer can see exactly what is proven and what is not.

---

## Slide 7 — Where It Hurts Most: One Consequential Action

### On the slide

**Beachhead:** AI-native B2B vendors (20–200 people) whose agent takes **write or spend** actions and whose enterprise deal is stuck in security review.

| Wedge | Example action | Why it matters |
|---|---|---|
| Fintech / support | Stripe refund or account change | Money movement; reviewer asks for attribution and scope |
| Cloud / devtools | AWS provisioning or GitHub change | Production impact; needs policy and evidence |
| Support ops | Customer-data or ticket update | Privacy and audit exposure |
| Procurement | Purchase or vendor action | Spend authority and approval trail |

**Later adjacencies:** agent-to-agent commerce, DeFi/on-chain execution, Web2 action verification at scale.

**Start with one action, one reviewer, one evidence pack.**

### Speaker notes

We are not selling a universal “agent economy” protocol on day one. We are selling a six-week design-partner pilot that instruments one action and produces evidence a reviewer will accept.

The design partner offer: free six weeks, sandbox credentials only, one action, verification page, tabletop security review, then $1,500/month if the evidence answers the reviewer.

---

## Slide 8 — Market & Timing: A Security Budget, Not a Token Narrative

### On the slide

**Category:** AI agent security, governance, and action assurance.

| Source | Signal | Caveat |
|---|---|---|
| Gartner, Feb 2026 | AI governance spending **$492M in 2026 → >$1B by 2030** | Governance platforms, broad definition |
| Agent OS, 2026 | Agent governance **$290M in 2025 → $2.3B by 2028** | Vendor research; directional |
| Meticulous Research, Sep 2026 | Agent management/gateways/identity/eval **$1.0–1.5B in 2026 → $15–22B by 2033** | Broad category definition |
| CB Insights, Sep 2026 | **163 private companies** in AI agent security/risk | Count of companies, not revenue |

**Why now**

- Enterprise agents are in production; audit trails are the missing control.
- EU AI Act, SOC 2/AICPA draft guidance, and customer security reviews are converging on evidence.
- MCP normalizes tool access; AP2/x402 normalize payments. Execution evidence is the missing layer.
- Identity vendors are validating the category, not solving the evidence problem.

**Our wedge**

- TAM: dedicated agent governance/security, roughly **$0.5–1.5B in 2026** depending on definition.
- SAM: AI-native B2B vendors with at least one write/spend agent and an enterprise security review; bottom-up sizing in diligence.
- SOM: **3 design partners in 6 months; 10 paid accounts in 18 months** at $18k–$42k ACV.

### Speaker notes

We use market ranges because the category is being defined in real time. The important signal is not a precise TAM; it is that identity, observability, governance, and payment vendors are all converging on agent actions, and none owns the per-action evidence layer.

We are not dependent on a new blockchain or token cycle. The buyer already has a security budget and a stalled deal.

---

## Slide 9 — Competition: Receipts Are Not Enough

### On the slide

| Category | Examples | What they do well | What they do not solve |
|---|---|---|---|
| Identity / access | Okta, Microsoft Entra Agent ID, Hush, Oasis, Astrix | Agent inventory, lifecycle, access policy, runtime control | Portable per-action evidence with credential and outcome binding |
| Observability / gateways | LangSmith, Arize, Portkey, Cloudflare AI Gateway | Traces, evals, cost, routing, guardrails | Signed enforcement evidence; provider-side proof |
| Governance / GRC | Credo AI, Geordie, ModelOp, Holistic AI | Policy workflow, inventories, control mapping | Per-action enforcement and verifiable receipts |
| Receipt / verifiable execution | Dapr 1.18, PipeLab, Aqta, Zanii, Action State, agent-attestation | Signed action records, hash chains, transparency primitives | Enterprise enforcement + provider adapters + reviewer workflow |
| TEE / zk | Primus zkTLS, zkAgent, Proof-of-Guardrail | Strong request/inference attestations | Low-cost, broad Web2 coverage at v1 |
| Payments | AP2, x402 | Authorization and settlement | Execution evidence for the action behind the payment |

**Tessera’s position:** the only path that combines **per-action enforcement**, **scoped credential issuance**, **provider adapters**, **signed receipts**, **offline verification**, and **reviewer evidence packs** in one product.

### Speaker notes

The receipt primitive is becoming commodity. The moat is the execution path and the enterprise evidence workflow: policy, issuer adapters, credential scoping, tenant isolation, authority binding, revocation, and a reviewer-facing pack.

We should not position against identity or observability vendors as a replacement. We should position as the evidence layer they do not provide.

---

## Slide 10 — Business Model: SaaS + Usage, No Token

### On the slide

| Tier | Price | Included | Target |
|---|---:|---|---|
| Developer | $0 | 1,000 actions/month, 1 environment, community support | Open-source adoption |
| Team | **$1,500/month** (annual) | 250,000 actions/month, 3 environments, SSO, evidence packs, email support | AI-native vendor closing first enterprise deals |
| Growth | **$3,500/month** (annual) | 1,000,000 actions/month, 10 environments, custom policies, Slack support, quarterly review | Scaling vendor with multiple enterprise customers |
| Enterprise | **$40k+/year** | 5M+ actions, VPC/self-hosted, HSM, DPA, pen-test report, named support | Regulated enterprise / platform |
| Overage | $0.004/action | Beyond included volume | Aligns price with action value |

**Land:** free 6-week design partner pilot → $1,500/month.  
**Expand:** environments, volume, evidence packs, self-hosted/enterprise.  
**No token. No per-seat pricing. No new chain.**

### Speaker notes

The pricing tracks the value of the enterprise deal it unblocks, not the cost of compute. A $1,500/month line item can be approved inside a security/sales budget without a new platform procurement cycle.

We will validate gross margin and CAC with design partners; the model is intentionally usage-based because action volume grows with the customer’s agent footprint.

---

## Slide 11 — Traction & Roadmap: Working Code, No Pretend Customers

### On the slide

**Already built**

- Rust broker: authorize → policy → credential/grant → receipt → chain → verify
- Control plane and tenant portal: OIDC, environments, agent keys, actions, evidence, analytics
- Provider adapters: Stripe, AWS STS, GitHub; preview Slack/Zendesk/OpenAI/Anthropic
- SDKs: TypeScript, Python, LangChain, MCP adapter
- EIP-712 receipts, hash chains, Merkle anchoring, KMS/HSM bridge
- Open-source offline verifier; public tamper demo
- **300+ tests**; published npm packages and PyPI `tessera-verify==0.1.2`
- Local benchmarks: policy 4.70 µs; EIP-712 sign 23.42 µs; HTTP authorize p50 3.87 ms in-memory / 8.12 ms Postgres; offline verify ~1.0 ms

**Not yet**

- Hosted GA and live OIDC provider validation
- Paid customers or design-partner case study
- SOC 2 report or external penetration test
- Production cloud/KMS benchmark
- Stripe billing launch

**Next 6–12 months**

| Phase | Milestones |
|---|---|
| 0–3 months | Hosted deployment; live OIDC; 3 design partners; first evidence pack |
| 3–6 months | Reviewer accepts evidence; 2 paid pilots; cloud/KMS benchmark |
| 6–12 months | SOC 2 readiness + pen test; 10 paid accounts; more provider adapters |

### Speaker notes

We are pre-revenue. The deck should say that plainly. What is unusual for pre-seed is the depth of the working system: the broker, control plane, portal, verifier, SDKs, test suite, security docs, and benchmarks are already in the repository.

The next milestone is not “build the protocol.” It is “get a real security reviewer to accept one evidence pack.”

---

## Slide 12 — Team & Ask

### On the slide

**Team**

**Founder:** [Name] — [2–3 lines: cryptography / distributed systems / AI / security / startup background]  
**Why us:** [the relevant proof point]  
**Hiring/contracting next:** security reviewer, design-partner engineer, GTM lead

**Ask**

Raising: **$1.0M–$1.5M pre-seed** on a **SAFE** *(draft; confirm final amount and terms)*  
Runway: **18 months**

**Use of funds**

- 50% engineering and security
- 20% design partners and GTM
- 15% compliance, audit, and penetration testing
- 15% infrastructure and operations

**Milestones unlocked**

- Hosted GA + live OIDC
- 3 design partners, 1 accepted evidence pack
- 2 paid pilots
- SOC 2 readiness and external pen test
- 10 paid accounts

**Investor help**

- Intros to AI-native B2B vendors with a stalled enterprise deal
- Security leaders who will review evidence
- Design partners with one write/spend agent in production

**Contact:** founders@thetessera.xyz

### Speaker notes

The ask is a draft until the founder confirms the amount and terms. The use of funds is deliberately security-heavy: the product’s credibility depends on a real deployment, a live identity provider, a cloud/KMS benchmark, and an independent security review.

We are not asking for a token launch or a chain. We are asking for the capital to turn a working security product into repeatable, paid design-partner evidence.

---

## Appendix A — What This Deck Deliberately Does Not Claim

- No production customers, revenue, or design-partner logos.
- No SOC 2 Type I/II report or completed external penetration test.
- No live Okta/Entra/Auth0 validation yet.
- No production cloud/KMS benchmark yet.
- No token, staking, slashing, TEE, zkVM, or zkTLS dependency.
- No claim that every provider action is broker-observed.
- No claim that receipts are immutable or tamper-proof; they are tamper-evident.
- No claim that evidence packs are a certification.

## Appendix B — Generic “Proof of Action” Deck Outline: What We Changed

The standard 10–12-slide outline is useful, but built for a decentralized agent-payment protocol. We adapted it:

| Generic recommendation | Tessera adaptation |
|---|---|
| TEE / zkTLS / zkVM / staking | Broker-mediated enforcement + EIP-712 receipts; explicit trade-off, no TEE/zk in v1 |
| Automatic settlement | Not the wedge; we produce execution evidence that can sit under AP2/x402 or enterprise workflows |
| Agent-to-agent commerce first | Enterprise write/spend actions first; A2A is adjacent |
| Token/protocol design | SaaS + usage; no token |
| “Proof of inference” competitors | Not our main competitor; identity, observability, governance, and receipt tools are closer |
| Traction slide with logos/grants | Working code, tests, packages, benchmarks; no pretend logos |
| Team slide | Placeholder until founder supplies background |
| Ask | Draft range and use of funds; founder must confirm |

## Appendix C — Source Registry

Use these as citation anchors; dates are publication/access dates.

- **S1** — Gartner, “Global AI Regulations Fuel Billion-Dollar Market for AI Governance Platforms,” 2026-02-17. https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms
- **S2** — Agent OS, “State of AI Agent Governance 2026,” 2026. https://vantageaiadvisory.com/agent-os/report-2026
- **S3** — Meticulous Research, “AI Agent Governance Platforms Outlook 2026–2033,” 2026-09-27. https://www.meticulousresearch.com/meticulous-next/ai-agent-governance-the-next-control-layer-for-enterprises
- **S4** — CB Insights, “AI agents are getting the keys,” 2026-09-24. https://research.cbinsights.com/ai-agents-are-getting-the-keys
- **S5** — Okta, “Okta for AI Agents” and Agent Gateway announcements, 2026. https://www.okta.com/products/govern-ai-agent-identity/
- **S6** — Microsoft Learn, “Governing Agent Identities,” 2026-11-11. https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview
- **S7** — LangSmith Observability, 2026. https://www.langchain.com/langsmith/observability
- **S8** — Arize, “6 LLM gateways to consider for production AI in 2026,” 2026-08-27. https://arize.com/resources/best-llm-gateways-comparison
- **S9** — Dapr / CNCF, “Introducing Verifiable Execution in Dapr 1.18,” 2026-06-11. https://www.cncf.io/blog/2026/06/11/introducing-verifiable-execution-in-dapr-1-18/
- **S10** — AP2 specification, 2026. https://ap2-protocol.org/ap2/specification/
- **S11** — x402 / agent payments comparison, 2026. https://emissar.ai/learn/agent-payments
- **S12** — PipeLab, “Agent Action Receipts,” 2026-05-21. https://pipelab.org/learn/agent-action-receipts
- **S13** — Aqta, “Receipts for the Age of Agents,” 2026. https://aqta.ai/manifesto
- **S14** — DCS Labs, “Can they prove what they did?,” 2026-10-18. https://dcslabs.ai/news/can-they-prove-what-they-did
- **S15** — Primus, “Verifiable AI Agent Execution,” 2026. https://docs.primuslabs.xyz/implementation-scenarios/provable-agent-execution/
- **S16** — Tessera repository: README, BENCHMARKS, architecture, security guarantees, receipt spec, pricing, design-partner program. Local source of truth.
- **S17** — Zanii, “Proof-of-Action for AI Agents,” 2026. https://proof.zanii.agency/zanii-proof-of-action.pdf
- **S18** — Action State / Data Phoenix, “Action State releases receipts for AI-agent actions,” 2026-10-22. https://dataphoenix.info/news/action-state-agent-evidence-tools
- **S19** — agent-attestation, Apache-2.0 receipts library. https://github.com/p-vbordei/agent-attestation
- **S20** — zkAgent, “Verifiable Agent Execution via One-Shot Complete LLM Inference Proof,” IACR 2026. https://iacr.org/news/item/27639
- **S21** — “Proof-of-Guardrail in AI Agents and What (Not) to Trust from It,” arXiv 2603.05786, 2026. https://arxiv.org/abs/2603.05786
- **S22** — Hush Security, $30M Series A, 2026-07-28. https://www.hush.security/resources/hush-security-raises-30m-to-close-the-ai-agent-governance-gap-with-akamai-joining-as-strategic-investor
- **S23** — Geordie AI, $30M Series A, 2026-05-28. https://www.geordie.ai/resources/geordie-raises-30m-to-help-enterprises-securely-adopt-agentic-ai-at-scale/
- **S24** — Eve Security, seed extension to $7.5M, 2026-09-15. https://www.prnewswire.com/news-releases/eve-security-extends-seed-round-to-7-5-million-as-rogue-ai-agents-turn-runtime-security-into-an-enterprise-imperative-302878598.html
- **S25** — Okta, Agent SSO / 34% survey, 2026-08-24. https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso

---

*Prepared from the Tessera repository and public market sources on 2026-11-12. Market estimates are third-party or vendor estimates, not audited facts; use ranges and cite the source. Complete the founder and ask placeholders before sending.*
