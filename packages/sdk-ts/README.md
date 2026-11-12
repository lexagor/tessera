# @tessera/sdk-ts

Broker ephemeral credentials for agent tool calls.

```bash
npm install @tessera/sdk-ts
```

```ts
import { createClient, wrapFn } from "@tessera/sdk-ts";

const tessera = createClient({
  endpoint: "https://api.tessera.example",
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
