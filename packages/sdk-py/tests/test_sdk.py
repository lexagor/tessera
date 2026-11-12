from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from tessera_verify import (
    AuthorizeInput,
    ProxyRequest,
    RecordInput,
    TesseraClient,
    TesseraConfig,
    TesseraHTTPError,
    hash_result,
    wrap,
    wrap_proxy,
)
from tessera_verify.wrap import canonicalize


def config() -> TesseraConfig:
    return TesseraConfig(
        endpoint="http://tessera.test",
        api_key="tsk_test",
        agent_id="billing-agent",
        user_id="user_1",
    )


class BrokerMock:
    def __init__(self, material: dict[str, Any] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict[str, Any]] = []
        self.material = material or {"kind": "grant", "grantId": "grant_1", "proxyRequired": True}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body: dict[str, Any] = json.loads(request.content) if request.content else {}
        self.bodies.append(body)
        if request.url.path == "/v1/authorize":
            return httpx.Response(
                200,
                json={
                    "decision": "allow",
                    "credential": {
                        "provider": "stripe",
                        "resource": "stripe:refunds.create",
                        "ttlSeconds": 30,
                        "singleUse": True,
                        "argsHash": "0xabc",
                        "material": self.material,
                        "issuanceId": "iss_1",
                    },
                    "receipt": {"v": 2, "agent": "billing-agent"},
                    "receiptId": "0xreceipt",
                    "actionId": "action_1",
                },
            )
        if request.url.path == "/v1/record":
            return httpx.Response(200, json={"status": "recorded"})
        if request.url.path == "/v1/proxy":
            return httpx.Response(
                200,
                json={
                    "status": 200,
                    "contentType": "application/json",
                    "body": "{}",
                    "actionId": "action_1",
                    "authorizationReceiptId": "0xreceipt",
                    "outcomeReceiptId": "0xoutcome",
                    "outcomeRecorded": True,
                },
            )
        if request.url.path == "/v1/verify/receipt":
            return httpx.Response(
                200,
                json={
                    "valid": True,
                    "recovered": "0xsigner",
                    "payloadHash": "0xhash",
                    "matchesExpected": True,
                },
            )
        if request.url.path == "/v1/revoke":
            return httpx.Response(
                200,
                json={
                    "event": {
                        "id": "evt_1",
                        "tenant": "acme",
                        "target": "grant_1",
                        "kind": "grant",
                    },
                    "grantRevoked": True,
                },
            )
        return httpx.Response(404, json={"error": {"message": "not found"}})

    def client(self) -> TesseraClient:
        http = httpx.Client(
            base_url="http://tessera.test",
            headers={"authorization": "Bearer tsk_test"},
            transport=httpx.MockTransport(self.handler),
        )
        return TesseraClient(config(), http_client=http)


def test_authorize_parses_credential_and_action() -> None:
    broker = BrokerMock()
    result = broker.client().authorize(
        AuthorizeInput(tool="stripe.refunds.create", intent="refund", args={"amount": 10})
    )
    assert result.decision == "allow"
    assert result.action_id == "action_1"
    assert result.credential is not None
    assert result.credential.material["grantId"] == "grant_1"


def test_proxy_sends_grant_and_returns_observed_outcome() -> None:
    broker = BrokerMock()
    response = broker.client().proxy(
        ProxyRequest(
            grant_id="grant_1",
            args_hash="0xabc",
            method="POST",
            path="/v1/refunds",
            body="amount=10",
        )
    )
    assert response.status == 200
    assert response.outcome_recorded is True
    assert broker.bodies[-1]["grantId"] == "grant_1"
    assert broker.bodies[-1]["argsHash"] == "0xabc"


def test_wrap_records_success_for_direct_bearer() -> None:
    broker = BrokerMock(material={"kind": "bearer", "token": "tok"})
    wrapped = wrap(
        broker.client(),
        "stripe.refunds.create",
        "refund",
        lambda args, credential: {"ok": args["amount"]},
    )
    assert wrapped({"amount": 10}) == {"ok": 10}
    record = [body for body in broker.bodies if "receiptId" in body][-1]
    assert record["status"] == "success"
    assert record["receiptId"] == "0xreceipt"


def test_wrap_records_failure_and_reraises() -> None:
    broker = BrokerMock(material={"kind": "bearer", "token": "tok"})

    def fail(_args: dict[str, Any], _credential: Any) -> None:
        raise RuntimeError("provider down")

    wrapped = wrap(broker.client(), "stripe.refunds.create", "refund", fail)
    with pytest.raises(RuntimeError, match="provider down"):
        wrapped({"amount": 10})
    record = [body for body in broker.bodies if "receiptId" in body][-1]
    assert record["status"] == "failure"
    assert record["errorClass"] == "RuntimeError"


def test_wrap_proxy_uses_grant_path() -> None:
    broker = BrokerMock()
    wrapped = wrap_proxy(
        broker.client(),
        "stripe.refunds.create",
        "refund",
        ProxyRequest(
            grant_id="ignored",
            args_hash="ignored",
            method="POST",
            path="/v1/refunds",
            body="amount=10",
        ),
    )
    response = wrapped({"amount": 10})
    assert response.outcome_recorded is True
    assert broker.bodies[-1]["grantId"] == "grant_1"
    assert broker.bodies[-1]["argsHash"] == "0xabc"


def test_record_and_verify_and_revoke() -> None:
    broker = BrokerMock()
    client = broker.client()
    client.record(RecordInput(receipt_id="0xreceipt", result_hash="0xhash", status="success"))
    verification = client.verify_receipt({"v": 2}, expected_signer="0xsigner")
    assert verification.valid is True
    assert verification.matches_expected is True
    revoked = client.revoke("grant_1")
    assert revoked.event.id == "evt_1"
    assert revoked.grant_revoked is True


def test_http_errors_are_typed() -> None:
    broker = BrokerMock()
    client = broker.client()
    with pytest.raises(TesseraHTTPError) as error:
        client._request("GET", "/v1/missing")
    assert error.value.status_code == 404


def test_canonicalization_and_hash_match_typescript() -> None:
    value = {"b": [2, 3], "a": 1, "nested": {"z": "x", "a": None}, "f": 1.0}
    assert canonicalize(value) == '{"a":1,"b":[2,3],"f":1,"nested":{"a":null,"z":"x"}}'
    assert hash_result(value) == "0x057ba76822d22802361b60e4f61ca3273621576def672a38215a3fe051a7ccad"
