"""SDK types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class PrincipalInput:
    principal_id: str
    authority_ref: str
    authority_hash: str
    principal_type: str | None = None
    verified_at: str | None = None
    verification_method: str | None = None


@dataclass
class AgentMetadataInput:
    agent_version: str | None = None
    model_id: str | None = None
    operator_id: str | None = None
    environment: str | None = None


@dataclass
class TesseraConfig:
    endpoint: str
    api_key: str
    agent_id: str
    user_id: str
    default_ttl_seconds: int = 30
    principal: PrincipalInput | None = None
    agent_meta: AgentMetadataInput | None = None
    timeout_seconds: float = 30.0


@dataclass
class AuthorizeInput:
    tool: str
    intent: str
    args: dict[str, Any] = field(default_factory=dict)
    tool_schema_hash: str | None = None
    principal: PrincipalInput | None = None
    agent_meta: AgentMetadataInput | None = None
    requested_scopes: list[str] | None = None
    risk_class: str | None = None
    declared_purpose: str | None = None
    authority_token: str | None = None


@dataclass
class EphemeralCredential:
    provider: str
    resource: str
    ttl_seconds: int
    single_use: bool
    args_hash: str
    material: dict[str, Any]
    reference: str | None = None
    issuance_id: str | None = None


@dataclass
class AuthorizeResult:
    decision: str  # "allow" | "deny"
    credential: EphemeralCredential | None
    receipt: dict[str, Any]
    receipt_id: str
    action_id: str | None = None


@dataclass
class RecordInput:
    receipt_id: str
    result_hash: str
    status: str = "success"
    error_class: str | None = None
    external_ref: str | None = None
    completed_at: str | None = None


@dataclass
class ProxyRequest:
    grant_id: str
    args_hash: str
    method: str
    path: str
    query: list[tuple[str, str]] = field(default_factory=list)
    content_type: str | None = None
    body: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "grantId": self.grant_id,
            "argsHash": self.args_hash,
            "method": self.method,
            "path": self.path,
            "query": [list(item) for item in self.query],
        }
        if self.content_type is not None:
            payload["contentType"] = self.content_type
        if self.body is not None:
            payload["body"] = self.body
        return payload


@dataclass
class ProxyResponse:
    status: int
    content_type: str | None
    body: str
    action_id: str | None = None
    authorization_receipt_id: str | None = None
    outcome_receipt_id: str | None = None
    outcome_receipt: dict[str, Any] | None = None
    outcome_recorded: bool = False


@dataclass
class AnchorBatch:
    root: str
    count: int
    leaves: list[str]
    calldata: str
    proof: list[str]


@dataclass
class ProposedPolicy:
    policy: dict[str, Any]
    evidence: list[Any]
    notes: list[str]


@dataclass
class RevocationEvent:
    id: str
    tenant: str
    target: str
    kind: str
    reason: str | None = None
    created_at: str | None = None


@dataclass
class RevokeOutcome:
    event: RevocationEvent
    provider: str | None = None
    capability: str | None = None
    grant_revoked: bool | None = None
    credential_revoked: bool | None = None


@dataclass
class ReceiptVerification:
    valid: bool
    recovered: str
    payload_hash: str
    matches_expected: bool | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class ChainVerification:
    valid: bool
    length: int
    recovered: str | None = None
    errors: list[str] = field(default_factory=list)


RevokeKind = Literal["grant", "agent", "credential"]
