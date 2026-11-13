# Subprocessors

**Last updated:** 2026-11-13

Tessera uses the following subprocessors for the hosted service. This list excludes
subprocessors used only for the public open-source repository or optional customer-controlled
deployments.

| Subprocessor | Purpose | Data location | Status |
|---|---|---|---|
| IONOS | Virtual private server, network, and disk hosting | European Union | Active |
| Auth0 | OIDC authentication, session initiation, identity provider | United States / global edge | Active |
| GitHub | Source hosting, CI, container registry, release artifacts | United States | Active |
| Resend | Transactional email delivery (when `EMAIL_PROVIDER=resend`) | United States | Optional |
| Customer-selected S3-compatible storage | Evidence pack storage (when `EVIDENCE_S3_*` is configured) | Customer-controlled | Optional |
| Stripe | Subscription billing and customer portal | United States | Disabled (billing not live) |

We do not use advertising, analytics, or data-broker subprocessors. The service uses the
customer's own OIDC provider for enterprise SSO when configured. We will update this page
before adding a subprocessor that processes customer content, and workspace owners may object
on reasonable data-protection grounds.

## Security and contracts

Subprocessors are selected for security and reliability and are bound by confidentiality and
data-protection terms appropriate to their role. The current list does not constitute a
representation that a subprocessor holds any particular certification. Contact
`privacy@thetessera.xyz` for the current DPA and transfer documentation.
