"""Tessera Python SDK.

Broker ephemeral, intent-validated credentials for agent tool calls.
"""

from .client import TesseraClient, create_client
from .errors import TesseraError, TesseraHTTPError, TesseraTransportError
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
    RevokeOutcome,
    TesseraConfig,
)
from .wrap import canonicalize, hash_result, wrap, wrap_proxy

__all__ = [
    "TesseraClient",
    "create_client",
    "wrap",
    "wrap_proxy",
    "hash_result",
    "canonicalize",
    "TesseraConfig",
    "TesseraError",
    "TesseraHTTPError",
    "TesseraTransportError",
    "PrincipalInput",
    "AgentMetadataInput",
    "AuthorizeInput",
    "AuthorizeResult",
    "EphemeralCredential",
    "RecordInput",
    "ProxyRequest",
    "ProxyResponse",
    "AnchorBatch",
    "ProposedPolicy",
    "RevocationEvent",
    "RevokeOutcome",
    "ReceiptVerification",
    "ChainVerification",
]
