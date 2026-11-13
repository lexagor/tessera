# Privacy Policy

**Effective:** 2026-11-13  
**Contact:** privacy@thetessera.xyz

Tessera provides an enforcement and evidence service for AI agent actions. This policy
describes the data processed through the hosted service at `app.thetessera.xyz`.

## Data we process

- **Account data:** name, email address, OIDC issuer/subject, organization membership, role.
- **Workspace data:** environments, agent metadata, policies, action records, outcomes,
  evidence packs, verification links, integrations, and audit logs.
- **Authentication data:** session identifiers and short-lived delegation/authority tokens.
- **Operational data:** request logs, IP address, user agent, timestamps, error information,
  and billing/plan state. We do not store payment card data; card processing is disabled while
  billing is not live.
- **Customer content:** data supplied through the API, broker, evidence packs, webhooks, or
  support requests. Production provider credentials added through integrations are encrypted at rest in the
  control plane; broker-held grants remain in the broker.

## How we use it

We process data to provide and secure the service, authenticate users, enforce tenant
isolation, produce and verify evidence, respond to support and security requests, prevent
abuse, and meet legal obligations. We do not sell customer data or use it to train public
foundation models.

## Legal bases

Where GDPR applies, we rely on contract performance for the hosted service, legitimate
interests for security and service improvement, consent where required, and legal obligation
where applicable. Customers are responsible for their own legal basis for the agent and
end-user data they submit.

## Retention

Workspace data is retained for the organization's configured retention period (default 365
days) unless a longer period is required for security, dispute resolution, or law. A deletion
request creates a 30-day grace period; after that, the operator purge workflow removes
control-plane data and broker tenant data in line with the DPA. Backup copies expire on the
backup retention schedule. Session and webhook-delivery records are pruned automatically.

## Subprocessors and disclosures

We use the subprocessors listed in [`subprocessors.md`](subprocessors.md). We may disclose
data if required by law, to protect rights and safety, or in connection with a merger,
acquisition, or asset transfer subject to appropriate confidentiality. We do not disclose
customer content to advertisers.

## Security

Controls include tenant-scoped authorization, row-level security for broker tables, encrypted
secrets, signed records, audit logs, access controls, rate limits, and encrypted transport.
No system is perfectly secure; report suspected issues to `security@thetessera.xyz`.

## International transfers

The service is hosted in the European Union (IONOS) and uses identity infrastructure operated
by Auth0. Where data is transferred outside the EEA/UK, we rely on appropriate safeguards such
as standard contractual clauses. Contact us for the current transfer documentation.

## Your rights

Depending on your jurisdiction, you may request access, correction, deletion, restriction,
portability, or objection, and may withdraw consent. Workspace owners can export workspace
metadata and request deletion in Settings. Authorized users can contact
`privacy@thetessera.xyz`; we may need to verify identity and coordinate with the workspace
owner.

## Children

The service is not directed to children under 16. Do not submit children's personal data.

## Changes

We will post material changes on this page and, where appropriate, notify workspace owners.
The effective date above identifies the current version.

## Contact

Privacy: `privacy@thetessera.xyz`  
Security: `security@thetessera.xyz`  
Partners: `partners@thetessera.xyz`
