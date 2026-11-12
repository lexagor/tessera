# tessera (Python SDK)

Broker ephemeral, intent-validated credentials for agent tool calls.

```python
from tessera import create_client, wrap, TesseraConfig, hash_result

client = create_client(TesseraConfig(
    endpoint="http://localhost:8787",
    api_key="tsk_demo_local",
    agent_id="billing-agent",
    user_id="user_42",
))

def charge(args, credential):
    # Bind the ephemeral credential to your provider client for this call only.
    return stripe.charges.create(**args, api_key=credential.material["token"])

charge_refund = wrap(client, "stripe.charges.create", "refund an order", charge)
charge_refund({"amount": 100, "currency": "usd"})
```

The wrapper authorizes, runs your callback with the ephemeral credential, and records the
outcome (`hash_result` is a canonical 32-byte hash). Raise from the callback and the SDK records
a `failure` outcome before re-raising.
