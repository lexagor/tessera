"""Tessera Python SDK.

Broker ephemeral, intent-validated credentials for agent tool calls.
"""

from .client import TesseraClient, create_client
from .types import (
    AgentMetadataInput,
    AuthorizeInput,
    AuthorizeResult,
    EphemeralCredential,
    PrincipalInput,
    RecordInput,
    TesseraConfig,
)
from .wrap import hash_result, wrap

__all__ = [
    "TesseraClient",
    "create_client",
    "wrap",
    "hash_result",
    "TesseraConfig",
    "PrincipalInput",
    "AgentMetadataInput",
    "AuthorizeInput",
    "AuthorizeResult",
    "EphemeralCredential",
    "RecordInput",
]
