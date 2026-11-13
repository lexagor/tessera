# Plans and Billing Status

**Billing is not enabled in the current design-partner deployment.** There is no checkout,
subscription, or card charge. Usage limits still apply to protect the shared service.

## Current offer

The design-partner program is a free six-week pilot: one consequential action, sandbox
credentials, a verification page, and a tabletop security review. Commercial terms for a paid
deployment are agreed in a written order form after the pilot. Public list pricing is
intentionally withheld until billing and the support model are live.

## Plan limits

The hosted evaluation uses internal plan limits for actions, environments, and seats. The
API returns the current limits on `GET /v1/billing`; the portal shows usage in Settings.
Limits are operational controls, not a public price list.

## Enterprise

Enterprise deployment, customer-managed keys/KMS, VPC/self-hosting, DPA terms, and named
support are scoped separately. Contact `partners@thetessera.xyz`.

## Open source

The verifier, receipt schemas, and broker core are open source under their repository
licenses. The hosted service, evidence packs, policy management, and support are separate.
