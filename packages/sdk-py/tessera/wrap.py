"""Function wrapper that brokers each call."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from .client import TesseraClient
from .types import AuthorizeInput, EphemeralCredential, RecordInput


def hash_result(value: Any) -> str:
    """Canonical 32-byte result hash (SHA-256; the broker only requires a 32-byte hash)."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode()).hexdigest()


def wrap(
    client: TesseraClient,
    tool: str,
    intent: str,
    fn: Callable[[dict[str, Any], EphemeralCredential], Any],
) -> Callable[..., Any]:
    """Return a callable that authorizes, executes with the credential, and records."""

    def brokered(args: dict[str, Any]) -> Any:
        result = client.authorize(AuthorizeInput(tool=tool, intent=intent, args=args))
        if result.decision != "allow" or result.credential is None:
            raise PermissionError("tessera: authorization denied")
        try:
            out = fn(args, result.credential)
            client.record(
                RecordInput(
                    receipt_id=result.receipt_id,
                    result_hash=hash_result(out),
                    status="success",
                )
            )
            return out
        except Exception as err:  # noqa: BLE001
            client.record(
                RecordInput(
                    receipt_id=result.receipt_id,
                    result_hash=hash_result({"error": str(err)}),
                    status="failure",
                    error_class=type(err).__name__,
                )
            )
            raise

    return brokered
