//! Tool-definition pinning: trust-on-first-use for MCP/tool manifests.
//!
//! Approval cannot be a one-time event: a server can change a tool's definition after review
//! (a "rug pull"). Pinning stores the canonical hash of the reviewed definition; authorize
//! calls for a pinned tool must present the same hash, and a mismatch is denied and recorded
//! in the tenant's tamper-evident ledger.
//!
//! The definition hash is `keccak256(canonical JSON)` over the *whole* definition the client
//! was given (name, description, input/output schema, annotations) — not just the
//! description, because flags like `readOnlyHint` change approval behaviour silently.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

/// Allowed tool-name characters (URL path segment and store key).
pub fn valid_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool.len() <= 256
        && tool
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPin {
    pub tenant: String,
    pub tool: String,
    /// Canonical hash of the approved definition (`0x…`, keccak-256).
    pub definition_hash: String,
    /// The approved definition itself, for reviewer diffing.
    pub definition: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait ToolPinStore: Send + Sync {
    async fn set(&self, pin: ToolPin) -> Result<(), BrokerError>;
    async fn get(&self, tenant: &str, tool: &str) -> Result<Option<ToolPin>, BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<ToolPin>, BrokerError>;
    async fn delete(&self, tenant: &str, tool: &str) -> Result<bool, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryToolPins {
    pins: Mutex<HashMap<(String, String), ToolPin>>,
}

impl MemoryToolPins {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ToolPinStore for MemoryToolPins {
    async fn set(&self, pin: ToolPin) -> Result<(), BrokerError> {
        self.pins
            .lock()
            .map_err(|_| BrokerError::Internal("tool pin store poisoned".into()))?
            .insert((pin.tenant.clone(), pin.tool.clone()), pin);
        Ok(())
    }

    async fn get(&self, tenant: &str, tool: &str) -> Result<Option<ToolPin>, BrokerError> {
        Ok(self
            .pins
            .lock()
            .map_err(|_| BrokerError::Internal("tool pin store poisoned".into()))?
            .get(&(tenant.to_string(), tool.to_string()))
            .cloned())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ToolPin>, BrokerError> {
        let mut pins: Vec<ToolPin> = self
            .pins
            .lock()
            .map_err(|_| BrokerError::Internal("tool pin store poisoned".into()))?
            .values()
            .filter(|pin| pin.tenant == tenant)
            .cloned()
            .collect();
        pins.sort_by(|a, b| a.tool.cmp(&b.tool));
        Ok(pins)
    }

    async fn delete(&self, tenant: &str, tool: &str) -> Result<bool, BrokerError> {
        Ok(self
            .pins
            .lock()
            .map_err(|_| BrokerError::Internal("tool pin store poisoned".into()))?
            .remove(&(tenant.to_string(), tool.to_string()))
            .is_some())
    }
}

/// Hash of a tool definition as presented to the client.
pub fn definition_hash(definition: &serde_json::Value) -> String {
    crate::canonical::hash_json(definition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_bounded_and_path_safe() {
        assert!(valid_tool_name("stripe.refunds.create"));
        assert!(valid_tool_name("mcp__server__get_user"));
        assert!(valid_tool_name("agent:tool@v1"));
        assert!(!valid_tool_name(""));
        assert!(!valid_tool_name("../etc/passwd"));
        assert!(!valid_tool_name("a/b"));
        assert!(!valid_tool_name("a b"));
        assert!(!valid_tool_name(&"x".repeat(257)));
    }

    #[test]
    fn definition_hash_is_canonical() {
        let a = serde_json::json!({"name": "t", "inputSchema": {"b": 1, "a": 2}});
        let b = serde_json::json!({"inputSchema": {"a": 2, "b": 1}, "name": "t"});
        assert_eq!(definition_hash(&a), definition_hash(&b));
        let changed = serde_json::json!({"name": "t", "inputSchema": {"b": 1, "a": 3}});
        assert_ne!(definition_hash(&a), definition_hash(&changed));
    }
}
