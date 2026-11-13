# Tessera — Proof of Action for AI agents

**One-liner:** Tessera enforces what an agent may do — and produces a signed, independently
verifiable record of every action.

---

## The problem

Agents now move money, change records, and act on behalf of customers. Enterprise security
reviews stall because the vendor cannot answer four questions:

- Which agent acted, and for which human?
- What exact tool call was authorized, under which policy version?
- Which scoped credential did it receive?
- What actually happened — and can a third party verify the record was not altered?

Logs are self-asserted and mutable. IAM suites govern who the agent is and what app it can
reach; they do not produce portable, per-action evidence.

## The product

Tessera is the enforcement + evidence layer for agent actions:

1. **Enforce.** A drop-in SDK or proxy evaluates per-action policy and issues a scoped
   credential (or broker-held grant) for the exact tool call.
2. **Bind.** Each action produces a signed record that binds the agent, delegating human,
   intent, policy hash, tool definition, arguments, credential thumbprint, and outcome.
3. **Verify.** An open-source verifier checks the record offline, without trusting Tessera or
   the vendor.
4. **Prove.** A verification page and exportable evidence pack map records to the controls a
   security reviewer, auditor, or insurer asks for.

## Who it is for

**Beachhead:** AI-native B2B vendors (20–200 people) whose agent writes or spends in customer
systems and whose enterprise deal is stuck in security review.

**Trigger:** the customer's security team asks "how do you prevent the agent from doing
something it shouldn't?", "show me an audit trail", "can you prove it wasn't altered?", or
"how do you scope the agent's access?"

**Buyer:** CTO, Head of Security, or Head of Platform.

## Why now

- Agents have moved from read to write and spend; incidents are common and budgets exist.
- Standards have converged on short-lived, per-request credentials (OAuth 2.1, MCP, XAA).
- The identity layer is being bundled by Okta and Microsoft. The evidence layer is not.
- Regulation is directional: audit-ready now, EU AI Act high-risk obligations in 2027–2028.

## Differentiation

Tessera is the only path that combines **per-call enforcement**, **scoped credential
minting**, **intent- and authority-bound signed records**, and **offline verification** in one
execution path. Adjacent products have two or three of these; none ships all four with
provider adapters and an open verifier.

## Status

- Broker implemented: authorize, Stripe/GitHub/AWS STS adapters, signed receipts, hash chains,
  Merkle anchoring, revocation, quotas, KMS signing, independent verifier.
- 322 Rust tests; cross-language hashing parity with the TypeScript SDK.
- Receipt v2, the control plane, evidence portal, public site, and Auth0 login are live; billing and design-partner evidence are the remaining rollout work.
- **Pre-revenue.** Recruiting design partners.

## Business model

Platform fee + included volume + overage. Land at $1,500/month (annualized ~$18k ACV),
expand to $3,500/month with environments and evidence packs; enterprise at $40k+/year for
VPC/HSM/DPA. Not per seat.

## The ask

- **Design partners:** AI-native teams with one consequential agent action to instrument.
  Free 6-week pilot; convert to $1,500/month.
- **Investors:** pre-seed to reach repeatable paid pilots; the model targets ~$550k ARR by
  year two.

**Contact:** founders@thetessera.xyz
