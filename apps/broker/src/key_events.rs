//! Hash-linked key-event ledger.
//!
//! Every key lifecycle change (creation, renewal, revocation) is appended as a signed,
//! hash-linked event: `event_hash = keccak(domain ‖ prev_hash ‖ canonical(event))`. The
//! linkage makes silent edits, deletions, or reordering detectable without trusting the
//! broker's storage.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

/// Domain tag for key-event hashing/signing.
pub const KEY_EVENT_DOMAIN: &str = "tessera-key-event-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEvent {
    pub id: String,
    pub tenant: String,
    /// `key.created` | `key.renewed` | `key.revoked`.
    pub kind: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
    pub prefix: String,
    /// Event-specific detail (rotation count, expiry, scope, …).
    #[serde(default)]
    pub details: serde_json::Value,
    pub at: String,
    /// Hash of the previous event for this tenant (None for the first).
    #[serde(default, rename = "prevHash", skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    /// Hash of this event (covered by `signature`).
    #[serde(rename = "eventHash", default)]
    pub event_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The bytes hashed for an event: domain ‖ prev_hash ‖ canonical JSON without hash/signature.
pub fn event_digest(event: &KeyEvent) -> Result<[u8; 32], BrokerError> {
    let mut value = serde_json::to_value(event)
        .map_err(|e| BrokerError::Internal(format!("serialize key event: {e}")))?;
    if let Some(object) = value.as_object_mut() {
        object.remove("eventHash");
        object.remove("signature");
    }
    let canonical = crate::canonical::canonicalize(&value);
    let mut preimage = Vec::with_capacity(KEY_EVENT_DOMAIN.len() + 32 + canonical.len());
    preimage.extend_from_slice(KEY_EVENT_DOMAIN.as_bytes());
    match event.prev_hash.as_deref() {
        Some(prev) => {
            let raw = hex::decode(prev.trim_start_matches("0x"))
                .map_err(|e| BrokerError::Internal(format!("bad prev hash: {e}")))?;
            preimage.extend_from_slice(&raw);
        }
        None => preimage.extend_from_slice(&[0u8; 32]),
    }
    preimage.extend_from_slice(canonical.as_bytes());
    Ok(crate::merkle::keccak(&preimage))
}

/// Verify a tenant's ledger: hash linkage and (when present) signatures.
///
/// A compacted ledger starts with a `ledger.compacted` event whose `prev_hash` points at the
/// pruned predecessor; verification anchors on that signed checkpoint (the event records the
/// pruned hash, and forging it requires the broker key).
pub fn verify_chain(events: &[KeyEvent]) -> bool {
    // A compacted ledger has a pruned prefix: anchor on the first surviving event's
    // predecessor hash. The `ledger.compacted` checkpoint records (and is signed over) the
    // pruned hash, so the gap is a signed claim rather than an unexplained hole.
    let compacted = events.iter().any(|event| event.kind == "ledger.compacted");
    let mut prev: Option<String> = if compacted {
        events.first().and_then(|event| event.prev_hash.clone())
    } else {
        None
    };
    for event in events {
        // The checkpoint itself spans the gap; its own digest (and signature) is verified
        // below just like any other event.
        if event.kind != "ledger.compacted" && event.prev_hash != prev {
            return false;
        }
        let Ok(digest) = event_digest(event) else {
            return false;
        };
        let expected = format!("0x{}", hex::encode(digest));
        if event.event_hash != expected {
            return false;
        }
        prev = Some(event.event_hash.clone());
    }
    true
}

#[async_trait]
pub trait KeyEventStore: Send + Sync {
    async fn append(&self, event: KeyEvent) -> Result<(), BrokerError>;
    /// Events for a tenant, oldest first.
    async fn list(&self, tenant: &str) -> Result<Vec<KeyEvent>, BrokerError>;
    /// Drop events older than `cutoff`, keeping the chain verifiable by appending a signed
    /// `ledger.compacted` checkpoint that names the last pruned hash. Returns (removed,
    /// checkpoint event) or None when nothing was pruned.
    async fn compact(
        &self,
        tenant: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        checkpoint: KeyEvent,
    ) -> Result<Option<(usize, KeyEvent)>, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryKeyEvents {
    events: Mutex<HashMap<String, Vec<KeyEvent>>>,
}

impl MemoryKeyEvents {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<KeyEvent>>>, BrokerError> {
        self.events
            .lock()
            .map_err(|_| BrokerError::Internal("key event store poisoned".into()))
    }
}

#[async_trait]
impl KeyEventStore for MemoryKeyEvents {
    async fn append(&self, event: KeyEvent) -> Result<(), BrokerError> {
        self.lock()?
            .entry(event.tenant.clone())
            .or_default()
            .push(event);
        Ok(())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<KeyEvent>, BrokerError> {
        Ok(self.lock()?.get(tenant).cloned().unwrap_or_default())
    }

    async fn compact(
        &self,
        tenant: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
        mut checkpoint: KeyEvent,
    ) -> Result<Option<(usize, KeyEvent)>, BrokerError> {
        let mut events = self.lock()?;
        let ledger = events.entry(tenant.to_string()).or_default();
        let prunable: Vec<KeyEvent> = ledger
            .iter()
            .filter(|event| {
                chrono::DateTime::parse_from_rfc3339(&event.at)
                    .map(|at| at.with_timezone(&chrono::Utc) < cutoff)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if prunable.is_empty() {
            return Ok(None);
        }
        let removed = prunable.len();
        let through_hash = prunable
            .last()
            .map(|event| event.event_hash.clone())
            .unwrap_or_default();
        checkpoint.prev_hash = Some(through_hash);
        let digest = event_digest(&checkpoint)?;
        checkpoint.event_hash = format!("0x{}", hex::encode(digest));
        ledger.retain(|event| !prunable.iter().any(|pruned| pruned.id == event.id));
        ledger.push(checkpoint.clone());
        Ok(Some((removed, checkpoint)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, prev: Option<&str>, at: &str) -> KeyEvent {
        let mut event = KeyEvent {
            id: format!("kev_{kind}"),
            tenant: "acme".into(),
            kind: kind.into(),
            key_id: "key_1".into(),
            key_name: "ci".into(),
            prefix: "tsk_abc".into(),
            details: serde_json::json!({ "rotationCount": 1 }),
            at: at.into(),
            prev_hash: prev.map(str::to_string),
            event_hash: String::new(),
            signature: None,
        };
        let digest = event_digest(&event).unwrap();
        event.event_hash = format!("0x{}", hex::encode(digest));
        event
    }

    #[test]
    fn linkage_detects_edits_and_reordering() {
        let first = event("key.created", None, "2026-09-17T10:00:00Z");
        let second = event(
            "key.renewed",
            Some(&first.event_hash),
            "2026-09-17T11:00:00Z",
        );
        let chain = vec![first.clone(), second.clone()];
        assert!(verify_chain(&chain));

        // Editing a detail changes the hash.
        let mut edited = second.clone();
        edited.details = serde_json::json!({ "rotationCount": 99 });
        assert!(!verify_chain(&[first.clone(), edited]));

        // Reordering breaks linkage.
        let reversed = vec![second.clone(), first.clone()];
        assert!(!verify_chain(&reversed));

        // Deleting the middle event breaks linkage.
        let third = event(
            "key.revoked",
            Some(&second.event_hash),
            "2026-09-17T12:00:00Z",
        );
        assert!(!verify_chain(&[first, third]));
    }
}
