# Enterprise SSO and SCIM

## What is live

- Auth0 OIDC login for the hosted service, with `@thetessera.xyz` domain allowlist and
  first-admin bootstrap.
- SCIM 2.0 Users endpoint at `/scim/v2/Users` with an organization-scoped bearer token.
- Supported SCIM users: list/filter by `userName`, get, create, patch (`active`,
  `name.formatted`, `roles`), and delete/remove membership.
- Supported SCIM groups: list, create, patch members/display name, delete, with a Tessera role
  extension (`admin`, `member`, `viewer`).
- Token creation/revocation: `POST /v1/scim-tokens`, `DELETE /v1/scim-tokens/:id`.
- SCIM role values: `admin`, `member`, `viewer`. Owner is not provisionable through SCIM.

## SCIM example

Create a token in Settings or with an owner/admin session:

```bash
curl -X POST https://app.thetessera.xyz/v1/scim-tokens \
  -H 'content-type: application/json' -b "tessera_session=..." \
  -d '{"name":"Okta"}'
```

Then configure the IdP with the returned token:

```bash
curl https://app.thetessera.xyz/scim/v2/Users \
  -H "Authorization: Bearer scim_..."
```

The token is shown once and is scoped to one workspace. Revoke it immediately if it leaks.
The SCIM endpoint is proxied by Caddy at `/scim/*`; it is not a portal session endpoint.

## Customer-owned SSO

The recommended model is Auth0 Organizations with an Enterprise connection per customer:

1. Create an Auth0 organization for the Tessera workspace.
2. Add the customer's SAML/OIDC enterprise connection and verify their domain.
3. Enable organization discovery by email domain; require the organization on login.
4. Map the customer's IdP groups to Tessera roles using Auth0 rules/actions or SCIM groups
   with the Tessera SCIM Group role extension (or map roles through SCIM Users).
5. Test JIT provisioning, deprovisioning, MFA, and domain takeover defenses.
6. Configure the Auth0 custom domain and production email provider first.

Current limitation: the API uses one issuer/client (`OIDC_ISSUER`, `OIDC_CLIENT_ID`) and does
not yet expose per-org SSO configuration in the portal. SCIM Groups are available for role
mapping; self-service customer SSO remains a later feature. Auth0 can route multiple enterprise
connections through the same application, but the customer-specific organization/connection
setup requires Auth0 tenant administration. Do not claim self-service SSO until that UI and
per-org issuer model exist.

## Security requirements

- Use a dedicated SCIM token per IdP; never reuse a portal/API key.
- Rotate on personnel or IdP changes; revoke on offboarding.
- SCIM tokens can create users and change roles up to admin; treat them as privileged secrets.
- Do not allow SCIM to create owners or change billing/ownership without a second approval.
- Audit SCIM token creation/revocation and membership changes.
