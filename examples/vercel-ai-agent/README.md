# Vercel AI SDK example

Defines a normal Vercel AI SDK tool whose `execute` function is wrapped by the Tessera SDK.
Every model-initiated tool call is authorized, bound to the ephemeral credential returned by
the broker, and recorded.

```bash
pnpm install
TESSERA_ENDPOINT=http://localhost:8787 \
TESSERA_API_KEY=tsk_demo_local \
pnpm --filter @tessera/example-vercel-ai-agent typecheck
```

To use it with a model, add `@ai-sdk/openai` and call `generateText` as shown in
`index.ts`. Replace `refundProvider` with the real Stripe (or other provider) client and bind
`credential.material.token` for that one call.

If the agent key is token-delegated, set `TESSERA_AUTHORITY_TOKEN` to a short-lived value from
`POST /v1/authority-tokens`.
