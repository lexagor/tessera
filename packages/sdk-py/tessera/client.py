"""Tessera client."""

from __future__ import annotations

from typing import Any

import httpx

from .types import (
    AgentMetadataInput,
    AuthorizeInput,
    AuthorizeResult,
    EphemeralCredential,
    PrincipalInput,
    RecordInput,
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


class TesseraClient:
    def __init__(self, config: TesseraConfig) -> None:
        self._config = config
        self._http = httpx.Client(
            base_url=config.endpoint,
            headers={"authorization": f"Bearer {config.api_key}"},
            timeout=30.0,
        )

    @staticmethod
    def _mutation_headers(idempotency_key: str | None) -> dict[str, str]:
        """Headers for mutating calls; an idempotency key makes retries safe."""
        headers: dict[str, str] = {}
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        return headers

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
        body.update({k: v for k, v in optional.items() if v is not None})
        res = self._http.post(
            "/v1/authorize",
            headers=self._mutation_headers(idempotency_key),
            json=body,
        )
        res.raise_for_status()
        data: dict[str, Any] = res.json()
        cred = data.get("credential")
        credential = (
            EphemeralCredential(
                provider=cred["provider"],
                resource=cred["resource"],
                ttl_seconds=cred["ttlSeconds"],
                single_use=cred["singleUse"],
                args_hash=cred["argsHash"],
                material=cred["material"],
                reference=cred.get("reference"),
                issuance_id=cred.get("issuanceId"),
            )
            if cred
            else None
        )
        return AuthorizeResult(
            decision=data["decision"],
            credential=credential,
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
        self._http.post(
            "/v1/record",
            headers=self._mutation_headers(idempotency_key),
            json=body,
        ).raise_for_status()


def create_client(config: TesseraConfig) -> TesseraClient:
    return TesseraClient(config)
