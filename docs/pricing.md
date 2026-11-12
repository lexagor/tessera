# Pricing

Platform fee + included volume + overage. The price tracks the value of the enterprise deal it
unblocks, not the cost of compute. Never per seat.

| Tier | Price | Included | Target |
|---|---:|---|---|
| **Developer** | $0 | 1,000 actions/month, 1 environment, community support | Open-source adoption |
| **Team** | **$1,500/month** (annual) | 250,000 actions/month, 3 environments, SSO, evidence packs, email support | AI-native vendor closing its first enterprise deals |
| **Growth** | **$3,500/month** (annual) | 1,000,000 actions/month, 10 environments, custom policies, Slack support, quarterly review | Scaling vendor with multiple enterprise customers |
| **Enterprise** | **$40k+/year** | 5M+ actions, VPC/self-hosted, HSM, DPA, pen-test report, named support | Regulated enterprise / platform |
| **Overage** | $0.004/action | Beyond included volume | Aligns price with value |

## Why $1,500/month works

It is roughly 1–2% of a $100k–$200k enterprise deal, and it is expensed as sales/security
enablement rather than a new security platform. The buyer can approve it without a CISO
procurement cycle. The account expands as the vendor adds enterprise customers and
environments.

## Pilot terms

- 3-month paid pilot at $1,500/month, convertible to $18k annual.
- Free 6-week design-partner pilot before the paid pilot.
- Success criteria: one consequential action instrumented; a security reviewer accepts the
  verification page or evidence pack; integration under two days.

## Frequently asked

**Do you charge per agent or per human?** No. Price per environment and action volume.

**Is verification free?** Yes. The verifier and schema are open source; issuance at scale,
evidence packs, policy, and the hosted service are paid.

**What counts as an action?** One authorize + record pair for one tool call. Retries with the
same idempotency key count once.

**Can we self-host?** Enterprise includes VPC/self-hosted. Team/Growth use the hosted service.
The broker core is open source.
