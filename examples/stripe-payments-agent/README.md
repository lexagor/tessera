# Example: Stripe payments agent

An agent refunds a charge without ever holding a raw Stripe secret key. Because Stripe has no
per-request STS, Tessera issues a broker-held **grant**; the agent sends the call through the
Tessera proxy, which redeems the single-use grant, re-checks the bound `argsHash`, and forwards
the request to Stripe with the narrowest restricted key.

```bash
TESSERA_ENDPOINT=http://localhost:8787 pnpm start
```

The broker must have `STRIPE_RESTRICTED_KEYS` configured (e.g. `refunds_create=rk_...`). A second
use of the same grant is rejected, and a call with different arguments is denied.
