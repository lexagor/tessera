# Auth0 Production Configuration

**Last updated:** 2026-11-13

The live tenant is a development Auth0 tenant (`dev-*.us.auth0.com`). Auth0 login, domain
allowlist, first-admin bootstrap, and RP-initiated logout work, but a custom domain and a
production email provider are not configured.

## Custom domain

1. Choose `auth.thetessera.xyz` (or another hostname) and add the CNAME/A records Auth0
   provides.
2. Verify the domain in Auth0; wait for certificate provisioning.
3. Update the Auth0 application callback, logout, web origin, and initiate-login URI.
4. Update production env: `OIDC_ISSUER`, `OIDC_REDIRECT_URI`, `OIDC_LOGOUT_URL`.
5. Test login, logout, and existing-session behavior before removing the old tenant URL.

Do not change the issuer until every user session can be re-established; existing OIDC
identities are bound to `(issuer, subject)`.

## Email provider

1. Configure Auth0's email provider (SMTP, SendGrid, SES, or another supported provider) with
   a verified sender domain.
2. Verify SPF/DKIM/DMARC for the sending domain.
3. Test verification, passwordless (if enabled), and invitation emails.
4. Keep app-level transactional email separate (`EMAIL_PROVIDER=resend` or disabled). Auth0
   verification email is not the same as Tessera invite email.

## Cleanup

- Delete the temporary Management API M2M application and legacy auth application.
- Remove M2M credentials from local storage and the Auth0 dashboard.
- Rotate the application client secret if it was shared during setup.
- Require MFA for tenant administrators and restrict Management API scopes.

These steps require Auth0 dashboard or Management API credentials and are not automated by
this repository.
