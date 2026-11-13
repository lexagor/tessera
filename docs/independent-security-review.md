# Independent Security Review Package

**Status:** package for an external reviewer. No independent review has been completed.

## Scope

Invite review of the receipt/chain construction, authority-token binding, tenant/RLS
boundaries, broker proxy, webhook SSRF controls, evidence archive verification, and public
verifier. The threat model and controls matrix are the starting map, not proof.

## Reviewer access

- Read-only source access and the public repository.
- Staging tenant with synthetic data and sandbox providers.
- Test SCIM token and two isolated workspaces for cross-tenant testing.
- No production customer data, secrets, or signing keys.
- A named security contact and a 30-day disclosure window.

## Artifacts to provide

- `docs/threat-model.md`, `docs/controls-matrix.md`, `docs/architecture.md`.
- Receipt spec, verifier source, authority transition model, RLS script, and test suite.
- Architecture/data-flow diagrams, deployment manifests, and image digests.
- Incident-response, backup/restore, access, and vulnerability-management procedures.
- Prior penetration-test report and remediation status (when available).

## Questions for the reviewer

1. Can a receipt be forged or replayed without the signer, or can a verification path accept a
   malformed/ambiguous chain?
2. Does authority binding actually constrain tenant, agent, human, expiry, and single use?
3. Can a control-plane or broker query cross a tenant boundary despite RLS and application
   predicates?
4. Can the broker be induced to call an internal/metadata endpoint through webhooks, proxy, or
   provider islands?
5. Does evidence export/restore preserve integrity and access boundaries?
6. Are signing-key rotation, KMS failure, and revocation fail-closed?
7. Does the public verifier make any trust assumption it does not disclose?

## Deliverables

Written report with severity, exploitability, evidence, affected version/digest, and
remediation. A public summary only after remediation and customer consent. Do not convert an
engagement into a “certified” or “audited” claim; an independent code review is not a SOC 2
report.
