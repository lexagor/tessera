# Proof of Action

**Category:** agent action assurance / proof of action.

**One-liner:** Tessera enforces what an AI agent may do — and produces a signed,
independently verifiable record of every action.

## The problem

An AI-native vendor is losing an enterprise deal in security review. The customer's security
team asks four questions the vendor cannot answer with logs:

1. Which agent acted, and for which human?
2. What exact tool call was authorized, under which policy version?
3. Which scoped credential did it receive?
4. What actually happened — and can a third party verify the record was not altered?

IAM suites answer "who is the agent" and "what app can it reach." They do not bind the exact
tool call, the delegating human, the policy content, the credential, and the outcome into
portable evidence.

## What Tessera does

1. **Enforce.** A drop-in SDK, proxy, or MCP adapter evaluates per-action policy and issues a
   scoped credential — or a broker-held grant the agent never sees.
2. **Bind.** Each action produces a signed record that binds the agent, the delegating human,
   the intent, the policy hash, the tool definition, the arguments, the credential thumbprint,
   and the outcome.
3. **Verify.** The open-source verifier checks the record offline, without trusting Tessera or
   the vendor. Verification is free.
4. **Prove.** A verification page and exportable evidence pack map records to SOC 2,
   ISO 42001, EU AI Act Art. 12/26, FINRA, SEC 17a-4, and DORA.

## Beachhead ICP

**Primary:** AI-native B2B vendors, 20–200 people, selling an agentic product to enterprises,
where the agent takes **write or spend** actions in the customer's systems (support
automation, fintech ops, health admin, procurement, dev tools, sales ops).

**Trigger:** an enterprise deal is stuck in security review because the customer asked:

- "How do you prevent the agent from doing something it shouldn't?"
- "Show me an audit trail of what the agent did, on whose authority."
- "Can you prove the record wasn't altered?"
- "How do you scope the agent's access to our systems?"

**Buyer:** CTO, Head of Security, or Head of Platform. The economic buyer may be the CEO/COO
if the deal is large enough.

**Why this buyer:** the purchase unblocks revenue, the technical buyer appreciates the proof,
the approval path is short, and a scoped pilot budget can be approved without a new platform procurement cycle.

**Secondary:** regulated mid-market firms (fintech, insurance, health) that need an
action-level audit trail and cannot afford a Big-4 integration.

**Channel:** agent platforms and gateways that want to embed verification. Partner rather
than compete.

## Positioning

**Headline:** *Your enterprise buyer asked for proof. Here it is.*

**Subhead:** *Tessera enforces what your agent may do — and produces a signed, independently
verifiable record of every action.*

**Proof points:** per-action enforcement; scoped credential minting; offline verification;
open verifier; 10-minute integration; evidence mapped to the controls a reviewer asks for.

**CTA:** *Book a 30-minute Agent Security Review Readiness Audit.*

### Objections

| Objection | Response |
|---|---|
| "We already log everything." | Logs are self-asserted and mutable. Tessera produces a signed record a third party can verify without trusting you. |
| "Okta/Microsoft give us agent identity." | They govern who the agent is and what app it can reach. They do not bind the exact tool call, the human authority, and the outcome into portable proof. |
| "We can build this in-house." | You can; it takes 6–9 months and a security review. Tessera gives you the enforcement + proof loop in days, and the verifier is open source. |
| "Our customers don't ask for cryptographic proof." | They ask for audit trails, attribution, and retention. Tessera delivers those in a form their security team can verify. Cryptography is the how, not the what. |
| "You're a solo founder." | The core is open source, the verifier is independent, the security docs and test suite are public, and we will do a joint security review with your team. |

## Billing status

Billing is not enabled in the current design-partner deployment. See
[`pricing.md`](pricing.md). Commercial terms are agreed after the pilot; do not publish a
public price until checkout and support are live.

## What Tessera is not

Not an identity provider, an MCP gateway, an observability tool, a GRC platform, or a
blockchain product. Blockchain anchoring is optional; the default path uses signed records,
hash chains, and offline verification.

## 90-day proof plan

| Week | Focus | Deliverable |
|---|---|---|
| 1–4 | Discovery | 20 interviews; ICP memo; 3 pilot conversations |
| 1–3 | Technical proof | Receipt v2, open verifier, tamper demo |
| 3–6 | Design partners | 3 instrumented actions; verification page; tabletop security review |
| 6–8 | Evidence | Evidence pack accepted by one security reviewer |
| 8–10 | Convert | Agree commercial terms for the first paid pilot |
| 10–12 | Repeat | Second paid pilot; go/no-go on pre-seed or bootstrap |

**Go criteria:** 20 interviews by day 30, 3 design partners by day 60, 2 paid-pilot commitments by day 90,
one security reviewer accepts the evidence pack, one case study approved.

**Kill criteria (fallback if any two):** fewer than 3 of 20 interviews say security review is
a top-3 blocker; fewer than 2 design partners will instrument; no partner will agree commercial terms after a successful pilot; integration takes more than 2 days; an incumbent ships
vendor-side, offline-verifiable action receipts before day 90.

**Fallback:** the fintech action-control wedge (same broker, Stripe adapter, quotas), or
package the asset.
