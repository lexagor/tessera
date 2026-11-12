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
| Human authority | Optional HS256 authority-token verification; `verificationMethod` recorded |
| Tenancy | Tenant-scoped broker stores; Postgres RLS available for shared databases |
| Secrets | Provider secrets stay in the broker; Stripe grants envelope-encrypted at rest |
| Keys | Per-environment broker keys encrypted in the control plane; agent keys hashed |
| Access | Invite-only OIDC, HttpOnly sessions, RBAC, origin checks, audit log |
| Evidence export | Signed tenant archive with receipts, policy versions, authority transitions, key events, anchors |
| Standards | Agent Receipts v0.5.0 / W3C VC export with Ed25519 proof and optional RFC 3161 timestamp |
| API hardening | Request limits, timeouts, rate limits, no-store/nosniff headers, sanitized errors |

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

## Current limitations

- SOC 2 Type I/II and a third-party pen test are on the roadmap, not current claims.
- OIDC/JWKS authority verification is the next step beyond the current HS256 mode.
- SAML/SCIM, approvals, and multi-region HA are post-pilot work.
- The control plane is deployed on a single VPS for the first design partners.

## Subprocessors and infrastructure

- Hosting: operator-selected VPS (first pilots); Postgres, Redis, and optional S3-compatible
  object storage.
- Identity: the customer's OIDC provider.
- No model provider receives customer action data from Tessera.

## Contact

Security questions: `security@tessera.dev`
