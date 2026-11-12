"""PydanticAI tool whose provider call is authorized and recorded by Tessera."""

from __future__ import annotations

import os
from typing import Any

from pydantic_ai import Agent
from tessera_verify import TesseraConfig, create_client, wrap

client = create_client(
    TesseraConfig(
        endpoint=os.getenv("TESSERA_ENDPOINT", "http://localhost:8787"),
        api_key=os.getenv("TESSERA_API_KEY", "tsk_demo_local"),
        agent_id=os.getenv("TESSERA_AGENT_ID", "pydantic-ai-agent"),
        user_id=os.getenv("TESSERA_USER_ID", "user_42"),
        authority_token=os.getenv("TESSERA_AUTHORITY_TOKEN"),
    )
)


def refund_provider(args: dict[str, Any], credential: Any) -> dict[str, Any]:
    """Replace this with the real provider call.

    For a scoped bearer credential, bind `credential.material["token"]` to the provider
    client for this one call. For a broker-held grant, use `wrap_proxy` instead.
    """
    if credential.material.get("kind") != "bearer":
        raise ValueError("this example expects a scoped bearer credential")
    return {
        "refunded": True,
        "charge": args["charge"],
        "amount": args["amount"],
        "provider_credential": "present" if credential.material.get("token") else "missing",
    }


brokered_refund = wrap(
    client,
    "stripe.refunds.create",
    "refund a duplicate customer charge",
    refund_provider,
)

agent = Agent(
    "openai:gpt-4.1-mini",
    system_prompt="Use the refund tool only after confirming the charge is a duplicate.",
)


@agent.tool_plain
def refund(charge: str, amount: int) -> dict[str, Any]:
    """Refund one duplicate charge."""
    return brokered_refund({"charge": charge, "amount": amount})


if __name__ == "__main__":
    result = agent.run_sync("Refund charge ch_123 for 4200 cents because it is a duplicate.")
    print(getattr(result, "output", result))
