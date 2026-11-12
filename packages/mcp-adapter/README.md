# @tessera/mcp-adapter

MCP middleware that authorizes every `tools/call` through Tessera and injects the scoped
credential. Broker-held grants are observed and recorded by the broker.

```ts
import { createClient } from "@tessera/sdk-ts";
import { wrapMcpDispatcher } from "@tessera/mcp-adapter";

const dispatch = wrapMcpDispatcher(client, server.dispatch, {
  toolDefinitions,
  intentFor: (call) => `invoke ${call.name}`,
});
```

```bash
npm install @tessera/mcp-adapter
```
