"""Tool wrappers that broker each invocation through Tessera."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from Crypto.Hash import keccak

from .client import TesseraClient
from .types import AuthorizeInput, EphemeralCredential, ProxyRequest, ProxyResponse, RecordInput


def canonicalize(value: Any) -> str:
    """Deterministic JSON matching the TypeScript/Rust canonical form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: pair[0])
        return "{" + ",".join(
            f"{json.dumps(str(key), ensure_ascii=False)}:{canonicalize(item)}"
            for key, item in items
        ) + "}"
    return json.dumps(str(value), ensure_ascii=False, separators=(",", ":"))


def hash_result(value: Any) -> str:
    """Canonical Keccak-256 result hash, matching the TypeScript SDK."""
    digest = keccak.new(digest_bits=256)
    digest.update(canonicalize(value).encode("utf-8"))
    return "0x" + digest.hexdigest()


def _idempotency_key() -> str:
    return f"tessera-{uuid.uuid4()}"


def wrap(
    client: TesseraClient,
    tool: str,
    intent: str,
    fn: Callable[[dict[str, Any], EphemeralCredential], Any],
    *,
    authority_token: str | None = None,
) -> Callable[[dict[str, Any]], Any]:
    """Authorize, execute with the ephemeral credential, and record the outcome."""

    def brokered(args: dict[str, Any]) -> Any:
        idempotency_key = _idempotency_key()
        result = client.authorize(
            AuthorizeInput(
                tool=tool,
                intent=intent,
                args=args,
                authority_token=authority_token,
            ),
            idempotency_key=idempotency_key,
        )
        if result.decision != "allow" or result.credential is None:
            raise PermissionError("tessera: authorization denied")
        broker_observable = result.credential.material.get("kind") == "grant"
        try:
            out = fn(args, result.credential)
            if not broker_observable:
                client.record(
                    RecordInput(
                        receipt_id=result.receipt_id,
                        result_hash=hash_result(out),
                        status="success",
                    ),
                    idempotency_key=idempotency_key,
                )
            return out
        except Exception as err:
            if not broker_observable:
                client.record(
                    RecordInput(
                        receipt_id=result.receipt_id,
                        result_hash=hash_result({"error": str(err)}),
                        status="failure",
                        error_class=type(err).__name__,
                    ),
                    idempotency_key=idempotency_key,
                )
            raise

    return brokered


def wrap_proxy(
    client: TesseraClient,
    tool: str,
    intent: str,
    request: ProxyRequest,
    *,
    authority_token: str | None = None,
) -> Callable[[dict[str, Any]], ProxyResponse]:
    """Broker a broker-held grant and forward a proxy call; the broker observes the outcome."""

    def brokered(_args: dict[str, Any]) -> ProxyResponse:
        idempotency_key = _idempotency_key()
        result = client.authorize(
            AuthorizeInput(
                tool=tool,
                intent=intent,
                args=_args,
                authority_token=authority_token,
            ),
            idempotency_key=idempotency_key,
        )
        if result.decision != "allow" or result.credential is None:
            raise PermissionError("tessera: authorization denied")
        if result.credential.material.get("kind") != "grant":
            raise ValueError("tessera: wrap_proxy requires a broker-held grant credential")
        proxy_request = ProxyRequest(
            grant_id=result.credential.material["grantId"],
            args_hash=result.credential.args_hash,
            method=request.method,
            path=request.path,
            query=request.query,
            content_type=request.content_type,
            body=request.body,
        )
        return client.proxy(proxy_request, idempotency_key=idempotency_key)

    return brokered
