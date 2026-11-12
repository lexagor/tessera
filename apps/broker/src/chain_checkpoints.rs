//! Chain checkpoints: the head/count of each agent chain at the time it was archived.
//!
//! The sweep compares live chains against their checkpoint, so silent history rewrites or
//! lost receipts surface as drift alerts instead of going unnoticed.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCheckpoint {
    pub agent: String,
    /// Payload hash of the newest receipt when the checkpoint was taken.
    pub head: Option<String>,
    pub count: u64,
    pub taken_at: String,
}

/// Drift between a live chain and its checkpoint.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChainDrift {
    pub agent: String,
    /// `missing` (fewer receipts than checkpointed) or `rewritten` (prefix changed).
    pub kind: String,
    pub severity: u64,
    pub checkpoint_count: u64,
    pub live_count: u64,
}

#[async_trait]
pub trait ChainCheckpointStore: Send + Sync {
    async fn set(&self, tenant: &str, checkpoint: ChainCheckpoint) -> Result<(), BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<ChainCheckpoint>, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryChainCheckpoints {
    map: Mutex<HashMap<String, HashMap<String, ChainCheckpoint>>>,
}

impl MemoryChainCheckpoints {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChainCheckpointStore for MemoryChainCheckpoints {
    async fn set(&self, tenant: &str, checkpoint: ChainCheckpoint) -> Result<(), BrokerError> {
        self.map
            .lock()
            .map_err(|_| BrokerError::Internal("checkpoint store poisoned".into()))?
            .entry(tenant.to_string())
            .or_default()
            .insert(checkpoint.agent.clone(), checkpoint);
        Ok(())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<ChainCheckpoint>, BrokerError> {
        let mut checkpoints: Vec<_> = self
            .map
            .lock()
            .map_err(|_| BrokerError::Internal("checkpoint store poisoned".into()))?
            .get(tenant)
            .map(|agents| agents.values().cloned().collect())
            .unwrap_or_default();
        checkpoints.sort_by(|a, b| a.agent.cmp(&b.agent));
        Ok(checkpoints)
    }
}

/// Compare a live chain against a checkpoint.
pub fn detect_drift(
    checkpoint: &ChainCheckpoint,
    live_len: u64,
    live_head_at_checkpoint: Option<&str>,
    live_head: Option<&str>,
) -> Option<ChainDrift> {
    if live_len < checkpoint.count {
        return Some(ChainDrift {
            agent: checkpoint.agent.clone(),
            kind: "missing".into(),
            severity: checkpoint.count - live_len,
            checkpoint_count: checkpoint.count,
            live_count: live_len,
        });
    }
    if live_head_at_checkpoint != checkpoint.head.as_deref() {
        return Some(ChainDrift {
            agent: checkpoint.agent.clone(),
            kind: "rewritten".into(),
            // A rewritten prefix is an integrity failure; rank it above plain data loss.
            severity: u64::MAX / 2,
            checkpoint_count: checkpoint.count,
            live_count: live_len,
        });
    }
    let _ = live_head;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> ChainCheckpoint {
        ChainCheckpoint {
            agent: "agent-1".into(),
            head: Some("0xabc".into()),
            count: 3,
            taken_at: "2026-09-17T00:00:00Z".into(),
        }
    }

    #[test]
    fn drift_kinds_are_distinct() {
        assert!(detect_drift(&checkpoint(), 3, Some("0xabc"), Some("0xabc")).is_none());
        // Chain grew past the checkpoint: fine.
        assert!(detect_drift(&checkpoint(), 5, Some("0xabc"), Some("0xdef")).is_none());

        let missing = detect_drift(&checkpoint(), 1, Some("0xabc"), Some("0xabc")).unwrap();
        assert_eq!(missing.kind, "missing");
        assert_eq!(missing.severity, 2);

        let rewritten = detect_drift(&checkpoint(), 4, Some("0xdead"), Some("0xbeef")).unwrap();
        assert_eq!(rewritten.kind, "rewritten");
        assert!(rewritten.severity > missing.severity);
    }
}
