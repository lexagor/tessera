# @tessera/langchain

Broker every LangChain tool invocation through Tessera: authorize the exact tool call, inject
the scoped credential (or proxy a broker-held grant), and leave a signed outcome.

```bash
npm install @tessera/langchain @tessera/sdk-ts
```

```ts
import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";
import { wrapLangChainTool } from "@tessera/langchain";

const lookup = new DynamicStructuredTool({
  name: "lookup_customer",
  description: "Look up one customer",
  schema: z.object({ customerId: z.string() }),
  func: async ({ customerId }) => crm.lookup(customerId),
});

const brokeredLookup = wrapLangChainTool(tessera, lookup, {
  intent: "answer a support question about this customer",
  run: async (args, credential) => {
    if (credential.material.kind === "grant") {
      return tessera.proxy({
        grantId: credential.material.grantId,
        argsHash: credential.argsHash,
        method: "POST",
        path: "/v1/customers/lookup",
        body: JSON.stringify(args),
      });
    }
    return lookup.invoke(args);
  },
});
```

For broker-held grants the broker records the observed outcome; direct bearer credentials
report their own outcome through the SDK.
