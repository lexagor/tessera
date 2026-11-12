"""Tessera broker client."""

from __future__ import annotations

from typing import Any

import httpx

from .errors import TesseraHTTPError, TesseraTransportError
from .types import (
    AgentMetadataInput,
    AnchorBatch,
    AuthorizeInput,
    AuthorizeResult,
    ChainVerification,
    EphemeralCredential,
    PrincipalInput,
    ProposedPolicy,
    ProxyRequest,
    ProxyResponse,
    ReceiptVerification,
    RecordInput,
    RevocationEvent,
    RevokeKind,
    RevokeOutcome,
    TesseraConfig,
)


def _without_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _without_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_without_none(v) for v in value]
    return value


def _principal_dict(value: PrincipalInput | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return _without_none(
        {
            "principalId": value.principal_id,
            "principalType": value.principal_type,
            "authorityRef": value.authority_ref,
            "authorityHash": value.authority_hash,
            "verifiedAt": value.verified_at,
            "verificationMethod": value.verification_method,
        }
    )


def _agent_dict(value: AgentMetadataInput | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return _without_none(
        {
            "agentVersion": value.agent_version,
            "modelId": value.model_id,
            "operatorId": value.operator_id,
            "environment": value.environment,
        }
    )


def _error_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:500] or f"Tessera returned {response.status_code}"
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("code") or response.text[:500])
        if error:
            return str(error)
    return f"Tessera returned {response.status_code}"


def _credential(value: dict[str, Any] | None) -> EphemeralCredential | None:
    if not value:
        return None
    return EphemeralCredential(
        provider=value["provider"],
        resource=value["resource"],
        ttl_seconds=value["ttlSeconds"],
        single_use=value["singleUse"],
        args_hash=value["argsHash"],
        material=value["material"],
        reference=value.get("reference"),
        issuance_id=value.get("issuanceId"),
    )


class TesseraClient:
    def __init__(self, config: TesseraConfig, http_client: httpx.Client | None = None) -> None:
        self._config = config
        self._http = http_client or httpx.Client(
            base_url=config.endpoint,
            headers={"authorization": f"Bearer {config.api_key}"},
            timeout=config.timeout_seconds,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> TesseraClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        headers: dict[str, str] = {}
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        try:
            response = self._http.request(method, path, json=body, headers=headers)
        except httpx.HTTPError as error:
            raise TesseraTransportError(f"Tessera request failed: {error}") from error
        if response.status_code >= 400:
            try:
                payload = response.json()
            except ValueError:
                payload = response.text
            raise TesseraHTTPError(_error_message(response), response.status_code, payload)
        return response

    def authorize(
        self,
        payload: AuthorizeInput,
        idempotency_key: str | None = None,
    ) -> AuthorizeResult:
        principal: PrincipalInput | None = payload.principal or self._config.principal
        agent_meta: AgentMetadataInput | None = payload.agent_meta or self._config.agent_meta
        body: dict[str, Any] = {
            "agentId": self._config.agent_id,
            "userId": self._config.user_id,
            "tool": payload.tool,
            "intent": payload.intent,
            "args": payload.args,
        }
        optional = {
            "toolSchemaHash": payload.tool_schema_hash,
            "principal": _principal_dict(principal),
            "agentMeta": _agent_dict(agent_meta),
            "requestedScopes": payload.requested_scopes,
            "riskClass": payload.risk_class,
            "declaredPurpose": payload.declared_purpose,
            "authorityToken": payload.authority_token,
        }
        body.update({key: value for key, value in optional.items() if value is not None})
        data: dict[str, Any] = self._request(
            "POST",
            "/v1/authorize",
            body,
            idempotency_key,
        ).json()
        return AuthorizeResult(
            decision=data["decision"],
            credential=_credential(data.get("credential")),
            receipt=data.get("receipt", {}),
            receipt_id=data["receiptId"],
            action_id=data.get("actionId"),
        )

    def record(
        self,
        input: RecordInput,
        idempotency_key: str | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "agentId": self._config.agent_id,
            "receiptId": input.receipt_id,
            "resultHash": input.result_hash,
            "status": input.status,
        }
        if input.error_class is not None:
            body["errorClass"] = input.error_class
        if input.external_ref is not None:
            body["externalRef"] = input.external_ref
        if input.completed_at is not None:
            body["completedAt"] = input.completed_at
        self._request("POST", "/v1/record", body, idempotency_key)

    def proxy(
        self,
        request: ProxyRequest,
        idempotency_key: str | None = None,
    ) -> ProxyResponse:
        data: dict[str, Any] = self._request(
            "POST",
            "/v1/proxy",
            request.to_dict(),
            idempotency_key,
        ).json()
        return ProxyResponse(
            status=data["status"],
            content_type=data.get("contentType"),
            body=data.get("body", ""),
            action_id=data.get("actionId"),
            authorization_receipt_id=data.get("authorizationReceiptId"),
            outcome_receipt_id=data.get("outcomeReceiptId"),
            outcome_receipt=data.get("outcomeReceipt"),
            outcome_recorded=bool(data.get("outcomeRecorded")),
        )

    def anchor(self, agent_id: str) -> AnchorBatch:
        data: dict[str, Any] = self._request(
            "GET",
            f"/v1/chain/{agent_id}/anchor",
        ).json()
        return AnchorBatch(
            root=data["root"],
            count=data["count"],
            leaves=data.get("leaves", []),
            calldata=data["calldata"],
            proof=data.get("proof", []),
        )

    def submit_anchor(self, agent_id: str) -> dict[str, Any]:
        result: dict[str, Any] = self._request(
            "POST",
            f"/v1/chain/{agent_id}/anchor/submit",
        ).json()
        return result

    def propose_policy(self) -> ProposedPolicy:
        data: dict[str, Any] = self._request("GET", "/v1/policies/propose").json()
        return ProposedPolicy(
            policy=data.get("policy", {}),
            evidence=data.get("evidence", []),
            notes=data.get("notes", []),
        )

    def revoke(
        self,
        target: str,
        kind: RevokeKind = "grant",
        reason: str | None = None,
    ) -> RevokeOutcome:
        data: dict[str, Any] = self._request(
            "POST",
            "/v1/revoke",
            {"target": target, "kind": kind, "reason": reason},
        ).json()
        event = data.get("event", {})
        return RevokeOutcome(
            event=RevocationEvent(
                id=str(event.get("id", "")),
                tenant=str(event.get("tenant", "")),
                target=str(event.get("target", "")),
                kind=str(event.get("kind", kind)),
                reason=event.get("reason"),
                created_at=event.get("createdAt"),
            ),
            provider=data.get("provider"),
            capability=data.get("capability"),
            grant_revoked=data.get("grantRevoked"),
            credential_revoked=data.get("credentialRevoked"),
        )

    def verify_receipt(
        self,
        receipt: dict[str, Any],
        expected_signer: str | None = None,
        chain_id: int | None = None,
        verifying_contract: str | None = None,
    ) -> ReceiptVerification:
        body = dict(receipt)
        if expected_signer is not None:
            body["expectedSigner"] = expected_signer
        if chain_id is not None:
            body["chainId"] = chain_id
        if verifying_contract is not None:
            body["verifyingContract"] = verifying_contract
        data: dict[str, Any] = self._request("POST", "/v1/verify/receipt", body).json()
        return ReceiptVerification(
            valid=bool(data.get("valid")),
            recovered=str(data.get("recovered", "")),
            payload_hash=str(data.get("payloadHash", "")),
            matches_expected=data.get("matchesExpected"),
            errors=data.get("errors", []),
        )

    def verify_chain(
        self,
        entries: list[dict[str, Any]],
        chain_id: int | None = None,
        verifying_contract: str | None = None,
    ) -> ChainVerification:
        body: dict[str, Any] = {"entries": entries}
        if chain_id is not None:
            body["chainId"] = chain_id
        if verifying_contract is not None:
            body["verifyingContract"] = verifying_contract
        data: dict[str, Any] = self._request("POST", "/v1/verify/chain", body).json()
        return ChainVerification(
            valid=bool(data.get("valid")),
            length=int(data.get("length", 0)),
            recovered=data.get("recovered"),
            errors=data.get("errors", []),
        )


def create_client(config: TesseraConfig, http_client: httpx.Client | None = None) -> TesseraClient:
    return TesseraClient(config, http_client)
