//! Per-tenant alert routing: each tenant can point alerts at its own webhook.
//!
//! URLs are tenant-supplied, so they go through the same SSRF policy as tenant anchor RPC
//! URLs. Tokens are encrypted at rest with the tenant-secret envelope and never returned.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BrokerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertTarget {
    pub url: String,
    /// Shared secret sent as `x-tessera-alert-token` (encrypted at rest when stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Event types routed to this webhook; empty = all supported events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// Alerts at or below this severity are auto-acknowledged (counted, not delivered), so
    /// only meaningful escalations page anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_ack_below: Option<u64>,
}

#[async_trait]
pub trait AlertTargetStore: Send + Sync {
    async fn set(&self, tenant: &str, target: AlertTarget) -> Result<(), BrokerError>;
    async fn get(&self, tenant: &str) -> Result<Option<AlertTarget>, BrokerError>;
    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError>;
    async fn migrate(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryAlertTargetStore {
    targets: Mutex<HashMap<String, AlertTarget>>,
}

impl MemoryAlertTargetStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, AlertTarget>>, BrokerError> {
        self.targets
            .lock()
            .map_err(|_| BrokerError::Internal("alert target store poisoned".into()))
    }
}

#[async_trait]
impl AlertTargetStore for MemoryAlertTargetStore {
    async fn set(&self, tenant: &str, target: AlertTarget) -> Result<(), BrokerError> {
        self.lock()?.insert(tenant.to_string(), target);
        Ok(())
    }

    async fn get(&self, tenant: &str) -> Result<Option<AlertTarget>, BrokerError> {
        Ok(self.lock()?.get(tenant).cloned())
    }

    async fn delete(&self, tenant: &str) -> Result<bool, BrokerError> {
        Ok(self.lock()?.remove(tenant).is_some())
    }
}

/// Shared alert routing used by the scheduler and the services.
pub struct AlertRouter {
    store: Arc<dyn AlertTargetStore>,
    global_url: Option<String>,
    global_token: Option<String>,
    global_auto_ack_below: Option<u64>,
}

impl AlertRouter {
    /// Create backend tables (no-op for the in-memory store).
    pub async fn migrate(&self) -> Result<(), BrokerError> {
        self.store.migrate().await
    }

    pub fn new(
        store: Arc<dyn AlertTargetStore>,
        global_url: Option<String>,
        global_token: Option<String>,
    ) -> Self {
        Self {
            store,
            global_url,
            global_token,
            global_auto_ack_below: None,
        }
    }

    /// The auto-ack threshold for a tenant's alerts: the tenant's own policy wins, otherwise
    /// the operator-wide one.
    pub async fn auto_ack_below(&self, tenant: &str) -> Result<Option<u64>, BrokerError> {
        if let Some(target) = self.store.get(tenant).await? {
            if target.auto_ack_below.is_some() {
                return Ok(target.auto_ack_below);
            }
        }
        Ok(self.global_auto_ack_below)
    }

    pub fn with_auto_ack(mut self, threshold: Option<u64>) -> Self {
        self.global_auto_ack_below = threshold;
        self
    }

    /// The tenant's stored target, if any (used for config read-back).
    pub async fn target(&self, tenant: &str) -> Result<Option<AlertTarget>, BrokerError> {
        self.store.get(tenant).await
    }

    /// Whether an operator-wide fallback webhook is configured.
    pub fn has_global(&self) -> bool {
        self.global_url.is_some()
    }

    /// Store a tenant target.
    pub async fn set_target(&self, tenant: &str, target: AlertTarget) -> Result<(), BrokerError> {
        self.store.set(tenant, target).await
    }

    /// Remove a tenant target (alerts fall back to the operator webhook).
    pub async fn delete_target(&self, tenant: &str) -> Result<bool, BrokerError> {
        self.store.delete(tenant).await
    }

    /// Destination for an event: the tenant's own webhook when configured (and subscribed to
    /// the event), otherwise the operator-wide webhook.
    pub async fn destination(
        &self,
        tenant: &str,
        event: &str,
    ) -> Result<Option<(String, Option<String>)>, BrokerError> {
        if let Some(target) = self.store.get(tenant).await? {
            let subscribed = target.events.is_empty()
                || target.events.iter().any(|candidate| candidate == event);
            if subscribed {
                return Ok(Some((target.url, target.token)));
            }
        }
        Ok(self
            .global_url
            .clone()
            .map(|url| (url, self.global_token.clone())))
    }
}

/// Outcome of a webhook delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    /// Whether a destination existed and the request was made.
    pub attempted: bool,
    pub delivered: bool,
    pub status: Option<u16>,
}

impl Delivery {
    pub fn not_attempted() -> Self {
        Self {
            attempted: false,
            delivered: false,
            status: None,
        }
    }

    pub fn delivered(status: u16) -> Self {
        Self {
            attempted: true,
            delivered: true,
            status: Some(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn routing_prefers_the_tenant_webhook() {
        let store = Arc::new(MemoryAlertTargetStore::new());
        store
            .set(
                "acme",
                AlertTarget {
                    url: "https://hooks.acme.example/alerts".into(),
                    token: Some("tenant-token".into()),
                    events: vec!["anchor.gap".into()],
                    auto_ack_below: None,
                },
            )
            .await
            .unwrap();
        let router = AlertRouter::new(
            store.clone(),
            Some("https://hooks.operator.example/all".into()),
            Some("global".into()),
        );

        let (url, token) = router
            .destination("acme", "anchor.gap")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(url, "https://hooks.acme.example/alerts");
        assert_eq!(token.as_deref(), Some("tenant-token"));

        // Not subscribed to this event -> global fallback.
        let (url, _) = router
            .destination("acme", "key.expiring")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(url, "https://hooks.operator.example/all");

        // No tenant target -> global.
        let (url, _) = router
            .destination("other", "anchor.gap")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(url, "https://hooks.operator.example/all");

        // No global either -> nowhere (callers skip delivery).
        let bare = AlertRouter::new(store, None, None);
        assert!(bare
            .destination("other", "anchor.gap")
            .await
            .unwrap()
            .is_none());
    }
}
