# Security Contact and Response Targets

**Last updated:** 2026-11-13

## Reporting a vulnerability

Email `security@thetessera.xyz` with a description, reproduction steps, affected endpoint or
component, and any proof-of-concept. Do not access other tenants' data, run destructive tests,
or disclose the issue publicly before coordination. Encrypt sensitive reports if requested.

## Response targets

These are good-faith design-partner targets, not a contractual SLA:

| Severity | Examples | Initial response | Update cadence |
|---|---|---|---|
| Critical | Cross-tenant access, signing-key compromise, authentication bypass, remote code execution | 1 business day | Daily until contained |
| High | Stored XSS, SSRF to internal services, authorization flaw without immediate cross-tenant impact | 2 business days | Every 2 business days |
| Normal | Hardening gap, information disclosure, rate-limit bypass | 3 business days | Weekly |
| Informational | Best-practice suggestion, documentation issue | 5 business days | As needed |

We will confirm scope, coordinate a fix and disclosure window, and credit reporters who want
credit. We do not currently operate a paid bug bounty. `security@thetessera.xyz` is also the
contact for incident notifications under the [DPA](dpa.md).

## Operational contacts

- Security incidents: `security@thetessera.xyz`
- Privacy and data requests: `privacy@thetessera.xyz`
- Commercial and design-partner questions: `partners@thetessera.xyz`
