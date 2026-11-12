# PydanticAI example

A PydanticAI tool whose execution is brokered by the Tessera Python SDK.

```bash
cd examples/pydantic-ai-agent
python -m venv .venv && source .venv/bin/activate
pip install -e .
export OPENAI_API_KEY=...
export TESSERA_ENDPOINT=http://localhost:8787
export TESSERA_API_KEY=tsk_demo_local
python agent.py
```

`brokered_refund` authorizes the exact call, passes the ephemeral credential to the provider
callback, and records the result. Replace `refund_provider` with your real Stripe (or other
provider) client.

If the agent key uses per-call delegation, set `TESSERA_AUTHORITY_TOKEN` to a short-lived value
from `POST /v1/authority-tokens`.
