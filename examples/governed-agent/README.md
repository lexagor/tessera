# Example: governed agent

The full Tessera loop in one runnable agent: **authorize → execute → record → anchor**.

```bash
# 1. run a broker in demo mode
cd ../../apps/broker
BROKER_PORT=8787 TESSERA_DEMO_ALLOW=1 cargo run

# 2. run the agent (another terminal)
cd ../../examples/governed-agent
TESSERA_API_KEY=tsk_demo_local pnpm start
```

What happens:

1. **authorize** — the agent declares its intent; Tessera evaluates policy, brokers a
   credential, and returns a signed receipt.
2. **execute** — the agent uses the credential: directly for bearer/AWS credentials, or via
   the broker proxy when the credential is a broker-held grant.
3. **record** — the outcome is appended as a linked receipt in the agent's chain.
4. **anchor** — a Merkle anchor batch (root + calldata) is produced for the chain.

In demo mode the broker seeds the key `tsk_demo_local`. In production, create a key with
`curl -X POST $ENDPOINT/v1/keys -H "x-tessera-admin: $TESSERA_ADMIN_TOKEN" -d '{"tenant":"acme","name":"ci"}'`.
