# Integration & end-to-end tests

This directory holds integration tests that exercise the broker + API + SDKs together
once the implementations land. Suggested layout:

```
tests/
  integration/
    authorize.spec.ts        # allow/deny decisions end-to-end
    receipts.spec.ts         # receipt chain integrity + verification
    issuers.spec.ts          # AWS STS / GitHub / Stripe issuer adapters (mocked)
    revocation.spec.ts       # instant revocation propagation
  redteam/
    bypass.spec.ts           # args tampering, replay, forged intent
    injection.spec.ts        # prompt-injection-driven tool abuse
```

Run with `pnpm test` (Turbo) or the relevant runner per package.
