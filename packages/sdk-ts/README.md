# @tessera-verify/sdk-ts

Broker ephemeral credentials for agent tool calls.

```bash
npm install @tessera-verify/sdk-ts
```

```ts
import { createClient, wrapFn } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: "https://app.thetessera.xyz",
  apiKey: process.env.TESSERA_API_KEY!,
  agentId: "billing-agent",
  userId: "user_42",
});

const refund = wrapFn(
  tessera,
  { tool: "stripe.refunds.create", intent: "refund a duplicate charge" },
  async (args, credential) => {
    if (credential.material.kind !== "grant") throw new Error("expected a grant");
    return tessera.proxy({
      grantId: credential.material.grantId,
      argsHash: credential.argsHash,
      method: "POST",
      path: "/v1/refunds",
      body: new URLSearchParams(args as Record<string, string>).toString(),
    });
  },
);
```

For broker-held grants, the broker records the outcome it observes; the SDK does not
self-report it. Direct credentials still call `record()` after execution.

If an agent key uses per-call delegation, pass the short-lived token from
`POST /v1/authority-tokens` as `authorityToken` in the client config or in `wrapFn` metadata.
Owner-bound agent keys are minted automatically by the control plane; do not pass a token for
those keys.
