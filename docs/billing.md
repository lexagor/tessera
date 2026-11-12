# Billing

Tessera uses a platform subscription plus included action volume. Usage is metered from the
control-plane action read model; plan limits are enforced before an action is proxied to the
broker.

## Plans

| Plan | Monthly actions | Environments | Seats |
|---|---:|---:|---:|
| Developer | 1,000 | 1 | 2 |
| Team | 250,000 | 3 | 10 |
| Growth | 1,000,000 | 10 | 50 |
| Enterprise | 5,000,000 | 100 | 500 |

`GET /v1/usage` reports usage against the active plan. `POST /v1/billing/checkout` creates a
Stripe Checkout session for Team or Growth; `POST /v1/billing/portal` opens the Stripe billing
portal.

## Configuration

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_TEAM=price_...
STRIPE_PRICE_GROWTH=price_...
STRIPE_PORTAL_RETURN_URL=https://app.example.com/settings
```

If Stripe is not configured, billing endpoints return `503` and the portal shows usage/limits
without upgrade actions. The broker's Stripe issuer keys are separate from billing keys.

## Stripe webhook

Point Stripe at `POST /v1/webhooks/stripe`. The API verifies the Stripe signature and handles:

- `checkout.session.completed` — activates the subscription and sets the org plan.
- `customer.subscription.updated` — updates status/period/cancel-at-period-end.
- `customer.subscription.deleted` — downgrades to Developer and marks the subscription canceled.
- `invoice.payment_failed` — marks the subscription `past_due`.

## Enforcement

- Monthly action cap: authorize returns `402 plan_limit_exceeded` at the cap.
- Environment and seat caps are enforced on create/invite.
- Stripe checkout requires an `owner` or `admin`.
