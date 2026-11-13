# Trust Center

This page summarizes Tessera's security posture for design partners and their enterprise
reviewers. It is a working document, not a certification.

## What Tessera is

Tessera is the proof layer for agent actions. The Rust broker enforces per-action policy,
issues scoped credentials, and signs v2 action records. The control plane manages accounts,
environments, agent keys, and the action read model. The open verifier checks records without
trusting Tessera or the vendor.

## Controls today

| Area | Control |
|---|---|
| Enforcement | Deny-by-default CEL + deterministic constraints; per-action authorization |
| Credentials | Short-lived, scoped, `argsHash`-bound; broker-held grants for Stripe |
| Evidence | EIP-712 signed authorization + linked outcome records; broker-observed proxy outcomes; hash chains |
| Verification | Offline verifier for v1/v2 receipts, action pairs, chains, and Merkle proofs |
| Human authority | OIDC session can bind an agent key; the API mints short-lived HS256 tokens; the broker verifies issuer/audience, tenant/agent scope, expiry, and replay, then records `hmac-jwt` |
| Tenancy | Tenant-scoped stores; broker RLS forced on 9 tables; control-plane RLS forced on 18 tables with org/admin transaction context |
| Secrets | Provider secrets are encrypted at rest; Stripe grants are envelope-encrypted in the broker |
| Keys | Per-environment broker keys encrypted in the control plane; agent keys hashed |
| Access | Auth0 OIDC with first-admin bootstrap and `@thetessera.xyz` domain allowlist; invites for external workspaces; org-scoped SCIM Users token; HttpOnly sessions, RBAC, origin checks, audit log |
| Evidence export | Signed tenant archive with receipts, policy versions, authority transitions, key events, anchors |
| Standards | Agent Receipts v0.5.0 / W3C VC export with Ed25519 proof and optional RFC 3161 timestamp |
| API hardening | Request limits, timeouts, rate limits, no-store/nosniff headers, enforced CSP, sanitized errors |

## Reviewer evidence

Evidence packs include a reviewer report that maps signed action records to SOC 2, ISO 42001,
EU AI Act, NIST AI RMF, and DORA controls. A workspace owner can create a time-limited reviewer
link that lets an auditor read the report and download the signed archive without a Tessera
account. Revoking the link does not alter the underlying records.

## Data handling

- Raw tool arguments are not stored; receipts carry canonical hashes.
- Direct bearer/AWS outcomes are caller-reported; broker-held grants are observed and signed
  by the broker. Receipts label the source (`agent_reported` / `broker_observed`).
- The control plane stores action summaries and receipt IDs; receipts remain authoritative in
  the broker.
- Evidence packs are generated on demand and can be stored in S3-compatible object storage.
- Secrets are redacted from logs and debug output.
- Tenant export, deletion requests, retention settings, and the operator purge runbook are
  documented in [`data-lifecycle.md`](data-lifecycle.md).

## Current limitations

- SOC 2 Type I/II and a third-party pen test are on the roadmap, not current claims.
- Auth0 OIDC login is live. Direct broker-side OIDC/JWKS authority-token verification and
  enterprise Okta/Entra validation remain future work beyond the current API-minted HS256 mode.
- SCIM Users is implemented; SCIM Groups, self-service customer SSO, approvals, and multi-region HA are post-pilot work.
- The authority-token replay cache is Redis-backed when `REDIS_URL` is set; without Redis it
  is per-process, so multi-replica deployments must configure Redis for cross-replica replay
  protection.
- The control plane is deployed on a single VPS for the first design partners.
- Control-plane RLS is enabled behind `CONTROL_PLANE_RLS`; see
  [`control-plane-rls.md`](control-plane-rls.md) for rollback and canary steps.

## Subprocessors and infrastructure

- Hosting: IONOS VPS (European Union); Postgres, Redis, and optional S3-compatible object
  storage.
- Identity: Auth0 for the hosted service; customer-owned enterprise SSO is future work.
- Email: optional Resend transactional email.
- No model provider receives customer action data from Tessera.

See [`subprocessors.md`](subprocessors.md), [`privacy.md`](privacy.md), [`terms.md`](terms.md),
[`dpa.md`](dpa.md), and the draft [`security-policies.md`](security-policies.md).

## Contact

Security questions: `security@thetessera.xyz`
