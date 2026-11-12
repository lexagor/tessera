# Example: LangChain agent

Brokers a real `DynamicStructuredTool` invocation through Tessera.

```bash
# start the stack
docker compose -f ../../infra/docker/docker-compose.yml up -d postgres redis broker api
TESSERA_ENDPOINT=http://localhost:8787 TESSERA_API_KEY=... pnpm start
```

The example authorizes `lookupCustomer` with a declared intent, runs the original LangChain
tool with a scoped credential (or proxies a broker-held grant), and records the outcome.
