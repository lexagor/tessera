# tessera-verify (Python SDK)

Broker ephemeral, intent-validated credentials for agent tool calls.

```bash
pip install tessera-verify
```

```python
from tessera_verify import create_client, wrap, TesseraConfig, hash_result

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
outcome. `hash_result` produces the canonical Keccak-256 result hash used by the TypeScript SDK.
Raise from the callback and the SDK records a `failure` outcome before re-raising.

For broker-held grants, use `wrap_proxy` so the broker (not the agent) records the observed
outcome:

```python
from tessera_verify import ProxyRequest, wrap_proxy

refund = wrap_proxy(
    client,
    "stripe.refunds.create",
    "refund a test charge",
    ProxyRequest(
        grant_id="ignored-until-authorize",
        args_hash="ignored-until-authorize",
        method="POST",
        path="/v1/refunds",
        body="charge=ch_test&amount=50",
    ),
)
refund({"charge": "ch_test", "amount": 50})
```

The client also exposes `proxy`, `revoke`, `verify_receipt`, `verify_chain`, `anchor`,
`submit_anchor`, and `propose_policy`. See [`docs/publishing.md`](../../docs/publishing.md) for
the `tessera-verify` PyPI release flow.
