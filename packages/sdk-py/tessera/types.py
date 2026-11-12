"""SDK types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PrincipalInput:
    principal_id: str
    authority_ref: str
    authority_hash: str
    principal_type: Optional[str] = None
    verified_at: Optional[str] = None
    verification_method: Optional[str] = None


@dataclass
class AgentMetadataInput:
    agent_version: Optional[str] = None
    model_id: Optional[str] = None
    operator_id: Optional[str] = None
    environment: Optional[str] = None


@dataclass
class TesseraConfig:
    endpoint: str
    api_key: str
    agent_id: str
    user_id: str
    default_ttl_seconds: int = 30
    principal: Optional[PrincipalInput] = None
    agent_meta: Optional[AgentMetadataInput] = None


@dataclass
class AuthorizeInput:
    tool: str
    intent: str
    args: dict[str, Any] = field(default_factory=dict)
    tool_schema_hash: Optional[str] = None
    principal: Optional[PrincipalInput] = None
    agent_meta: Optional[AgentMetadataInput] = None
    requested_scopes: Optional[list[str]] = None
    risk_class: Optional[str] = None
    declared_purpose: Optional[str] = None
    authority_token: Optional[str] = None


@dataclass
class EphemeralCredential:
    provider: str
    resource: str
    ttl_seconds: int
    single_use: bool
    args_hash: str
    material: dict[str, Any]
    reference: Optional[str] = None
    issuance_id: Optional[str] = None


@dataclass
class AuthorizeResult:
    decision: str  # "allow" | "deny"
    credential: Optional[EphemeralCredential]
    receipt: dict[str, Any]
    receipt_id: str
    action_id: Optional[str] = None


@dataclass
class RecordInput:
    receipt_id: str
    result_hash: str
    status: str = "success"
    error_class: Optional[str] = None
    external_ref: Optional[str] = None
