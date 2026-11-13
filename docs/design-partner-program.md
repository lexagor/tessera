# Design Partner Program

A white-glove pilot for AI-native teams whose enterprise deal is stuck in security review. We
are recruiting **three** design partners to instrument one consequential agent action, produce
a verification page, and run a tabletop security review.

## Who it's for

AI-native B2B teams (20–200 people) that already do at least one of:

- give agents **write or spend** access (payments, refunds, provisioning, code review),
- connect agents to **SaaS tools** (Stripe, GitHub, Slack, internal APIs),
- have an **enterprise security review** asking for an audit trail, attribution, or proof of
  control.

Fintech, dev-tool, and vertical-agent companies are the best first fits.

## The offer

- **Free 6-week pilot.** Instrument one action; keep the receipts.
- **Agent Security Review Readiness Audit.** We review the questionnaire your enterprise
  customer sent, map the answers to evidence, and show what Tessera proves.
- **White-glove integration.** We pair with your engineer to wrap the first tool call end to
  end and produce a verification page.
- **Evidence pack.** JSON + human-readable export mapped to SOC 2, ISO 42001, EU AI Act
  Art. 12/26, FINRA, SEC 17a-4, and DORA.
- **Discuss a paid pilot** after the pilot if the evidence answers the reviewer.

## What we need

- One **agent action** to instrument (sandbox credentials only — never production secrets).
- ~2 hours/week from an engineer for the first two weeks.
- The enterprise security questionnaire or the reviewer's top questions, if available.
- Permission to reference you **only** if you choose to.

## Engagement plan (6 weeks)

| Week | Milestone |
|---|---|
| 1 | Kickoff; security-review questionnaire review; define the target action and success metric |
| 2 | Instrument the first action (`authorize` → execute/proxy → `record`); show the signed record |
| 3 | Verification page; independent verification in your CI or review flow |
| 4 | Policy: start permissive, then apply a least-privilege policy from observed traffic |
| 5 | Evidence pack; tabletop review with your security lead; revocation drill |
| 6 | Retrospective; decide on paid pilot, expansion scope, and next steps |

## Success criteria

- **≥1 consequential action** governed end to end.
- **A security reviewer accepts** the verification page or evidence pack.
- **Integration takes <2 days** for the partner's engineer.
- **A revocation drill** succeeds.
- You would **recommend it** to another team (NPS ≥ 8) — or tell us exactly why not.

## Data handling & security

- Core is **open source**; you can run the broker yourself.
- Credentials are **broker-held**; raw provider secrets are never exposed to the agent and are
  redacted from logs.
- Everything is **tenant-scoped**; API keys are revocable instantly.
- Start in a staging broker; nothing touches production by default.
- We will share the threat model, controls matrix, and audit readiness docs during the pilot.

## Outreach template

> **Subject:** Unblocking {team}'s enterprise agent deal — 6-week evidence pilot
>
> Hi {name},
>
> You mentioned {enterprise customer}'s security review is asking how the agent is scoped and
> what it did on whose authority. Tessera enforces that per action and produces a signed record
> a third party can verify offline.
>
> We're working with three AI-native teams to instrument one action, produce a verification
> page, and run a tabletop security review. Free for six weeks; if it answers the reviewer, we
> discuss commercial terms for a paid deployment.
>
> Worth a 20-minute call?
>
> — {sender}, {link}

## Discovery questions

1. What does your agent do today, and which credentials does it hold?
2. Which enterprise deal is stuck, and what did their security team ask for?
3. What tool calls would hurt most if hijacked (money, data, reputation)?
4. What proof do your auditors or customers ask for about agent behavior?
5. How do you revoke access today if a key leaks?
6. What would make this a must-have rather than a nice-to-have?

**Contact:** partners@thetessera.xyz
