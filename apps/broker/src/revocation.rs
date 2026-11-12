//! Revocation registry (fabric).
//!
//! Records revoked agents and grants. Agent revocation blocks new authorizations; grant
//! revocation also attempts issuer-specific invalidation (e.g. dropping a broker-held
//! Stripe grant).

use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationEvent {
    pub id: String,
    pub tenant: String,
    pub target: String,
    /// `"grant"` or `"agent"`.
    pub kind: String,
    pub reason: Option<String>,
    pub created_at: String,
}

#[async_trait]
pub trait RevocationStore: Send + Sync {
    async fn revoke(
        &self,
        tenant: &str,
        target: &str,
        kind: &str,
        reason: Option<String>,
    ) -> Result<RevocationEvent, BrokerError>;
    async fn is_revoked(&self, tenant: &str, target: &str) -> Result<bool, BrokerError>;
    async fn list(&self, tenant: &str) -> Result<Vec<RevocationEvent>, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

pub fn new_event(
    tenant: &str,
    target: &str,
    kind: &str,
    reason: Option<String>,
) -> RevocationEvent {
    RevocationEvent {
        id: format!("rev_{}", uuid::Uuid::new_v4().simple()),
        tenant: tenant.to_string(),
        target: target.to_string(),
        kind: kind.to_string(),
        reason,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

#[derive(Default)]
pub struct MemoryRevocationStore {
    events: Mutex<Vec<RevocationEvent>>,
}

impl MemoryRevocationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RevocationStore for MemoryRevocationStore {
    async fn revoke(
        &self,
        tenant: &str,
        target: &str,
        kind: &str,
        reason: Option<String>,
    ) -> Result<RevocationEvent, BrokerError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| BrokerError::Internal("revocation store poisoned".into()))?;
        events.retain(|e| !(e.tenant == tenant && e.target == target));
        let event = new_event(tenant, target, kind, reason);
        events.push(event.clone());
        Ok(event)
    }

    async fn is_revoked(&self, tenant: &str, target: &str) -> Result<bool, BrokerError> {
        let events = self
            .events
            .lock()
            .map_err(|_| BrokerError::Internal("revocation store poisoned".into()))?;
        Ok(events
            .iter()
            .any(|e| e.tenant == tenant && e.target == target))
    }

    async fn list(&self, tenant: &str) -> Result<Vec<RevocationEvent>, BrokerError> {
        let events = self
            .events
            .lock()
            .map_err(|_| BrokerError::Internal("revocation store poisoned".into()))?;
        Ok(events
            .iter()
            .filter(|e| e.tenant == tenant)
            .cloned()
            .collect())
    }
}

/// Whether a provider supports early credential invalidation, and how.
pub fn provider_capability(provider: &str) -> &'static str {
    match provider {
        // Broker-held grant: we can drop the secret immediately.
        "stripe" => "broker-grant-invalidation",
        // Provider supports revoking the credential via its API.
        "github" => "native",
        // STS credentials cannot be deleted, but a deny policy scoped to the session name
        // invalidates them within IAM's eventual-consistency window.
        "aws" => "deny-policy",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revoke_and_check() {
        let store = MemoryRevocationStore::new();
        assert!(!store.is_revoked("acme", "g1").await.unwrap());
        let event = store
            .revoke("acme", "g1", "grant", Some("leak".into()))
            .await
            .unwrap();
        assert_eq!(event.kind, "grant");
        assert!(store.is_revoked("acme", "g1").await.unwrap());
        assert_eq!(store.list("acme").await.unwrap().len(), 1);
        assert!(!store.is_revoked("other", "g1").await.unwrap());
    }

    #[tokio::test]
    async fn revoking_twice_is_idempotent() {
        let store = MemoryRevocationStore::new();
        store.revoke("acme", "a1", "agent", None).await.unwrap();
        store
            .revoke("acme", "a1", "agent", Some("again".into()))
            .await
            .unwrap();
        assert_eq!(store.list("acme").await.unwrap().len(), 1);
    }

    #[test]
    fn provider_capabilities() {
        assert_eq!(provider_capability("stripe"), "broker-grant-invalidation");
        assert_eq!(provider_capability("github"), "native");
        assert_eq!(provider_capability("aws"), "deny-policy");
    }
}
