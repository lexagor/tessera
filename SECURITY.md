# Security Policy

## Reporting a vulnerability

Do **not** open a public issue. Email `security@thetessera.xyz` with:
- a description and impact,
- reproduction steps or a proof of concept,
- affected versions/components.

Response targets are in [`docs/security-sla.md`](docs/security-sla.md). We will coordinate disclosure.

## Scope

Tessera sits on the critical path between agents and privileged resources. The highest-severity
classes are:

- credential/secret disclosure from the broker or secret store,
- authorization bypass (intent/scope/RBAC),
- receipt forgery or verification bypass,
- sandbox/issuer escape enabling cross-tenant action.

## Design commitments

- Ephemeral credentials are single-use and bound to an `args_hash`.
- Master secrets never enter agent runtime memory or logs.
- Every authorization decision produces a tamper-evident signed receipt.
