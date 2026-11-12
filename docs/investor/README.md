# Tessera Investor Materials

This directory contains four artifacts:

| File | Audience | Use |
|---|---|---|
| [`pitch-deck-human.md`](pitch-deck-human.md) | Humans | 12-slide narrative with speaker notes; convert to PDF/Notion for outreach |
| [`lightpaper-human.md`](lightpaper-human.md) | Humans | Notion-friendly technical memo and diligence appendix |
| [`pitch-deck-agent.md`](pitch-deck-agent.md) | AI agents | Structured deck + canonical facts + Q&A map for agent-assisted pitching |
| [`lightpaper-agent.md`](lightpaper-agent.md) | AI agents | Machine-readable technical facts, threat model, trade-offs, claims, limitations |

The site build excludes this directory, so these documents are not published at
`thetessera.xyz/docs/`.

## Before sending

1. Fill the founder/team slide with real background.
2. Confirm the raise amount and SAFE terms.
3. Add design-partner names only with permission.
4. Re-check market estimates and dates.
5. Keep the pre-revenue, no-SOC-2, no-pen-test, and no-live-IdP statements accurate.

## What changed from the generic “Proof of Action” outline

The supplied 10–12-slide outline assumes a decentralized agent-payment protocol with TEEs,
zk proofs, staking, and automatic settlement. Tessera is a different product:

- We are **broker-mediated enforcement + evidence**, not a trustless execution network.
- We use **EIP-712 receipts + hash chains + optional anchoring**, not TEE/zk in v1.
- We do **not** have a token, staking, slashing, or automatic settlement.
- Our beachhead is **enterprise write/spend agents**, not agent-to-agent commerce first.
- Our closest competitors are identity, observability, governance, and receipt tools — not
  only proof-of-inference projects.
- Our honest differentiation is **Level 1 broker-observed vs Level 2 caller-reported** evidence,
  plus provider adapters, scoped credentials, offline verification, and reviewer evidence packs.

## Source discipline

Market numbers come from third-party or vendor estimates with different category definitions.
Use ranges and cite the source. Do not present a TAM as an audited fact. Do not invent cloud
benchmarks or cost-per-action numbers; the repo has a cloud/KMS runbook but no production run yet.
